package com.asmolabs.vectispire.agent.kubernetes;

import com.asmolabs.vectispire.common.scanning.ContainerExecutor;
import com.asmolabs.vectispire.common.scanning.ContainerRun;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import com.asmolabs.vectispire.common.scanning.ContainerRunner.CollectedOutput;
import com.asmolabs.vectispire.common.scanning.ContainerRunner.ContainerResult;
import com.asmolabs.vectispire.common.scanning.ContainerRunner.OutputFile;
import com.asmolabs.vectispire.common.scanning.ScannerFailureException;
import com.asmolabs.vectispire.common.scanning.ScannerLimits;
import com.asmolabs.vectispire.common.scanning.scanners.ScannerImages;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Runs each {@link ContainerRun} as a pod, in a namespace of its own, on a cluster with no Docker
 * (decision 0045).
 *
 * <p><b>The closed shape, as far as a pod expresses it.</b> No capability, no new privilege, a read-only
 * root, the workspace owner's uid, seccomp {@code RuntimeDefault}, memory and CPU limits, no token, a fresh
 * pod deleted after its run; the namespace's Pod Security {@code restricted} refuses anything wider
 * whatever this class asks. What a pod cannot express is in 0045 §6, with its compensation.
 *
 * <p><b>Mounts are copied, not bound.</b> Each mount's content goes in over {@code exec} before the
 * scanner starts; a writable mount's new files come back after it ends ({@link MountArchives}).
 *
 * <p><b>Never empty.</b> Every way Kubernetes has of not running the scanner — an image that cannot be
 * pulled, a pod nobody schedules, a pod evicted, out of memory, the deadline, a read past its ceiling — is
 * a {@link ScannerFailureException} naming the step (0007). Nothing here answers a result the scanner did
 * not produce.
 */
public final class KubernetesExecutor implements ContainerExecutor {

    /**
     * @param namespace the scans' own namespace, labelled for Pod Security {@code restricted}
     * @param agent this agent's name, on every pod it starts: what it sweeps at start
     * @param helperImage a <b>static</b> busybox, pinned by digest — copied into the scanner's pod for the
     *     wrapper, so it must run in an image with no libc
     * @param defaultUser {@code uid:gid} for a run that names none: the workspace's owner, the agent's own
     * @param startTimeout how long a pod may take to be scheduled, pull its images and receive its
     *     workspace, before the scanner's own timeout starts
     * @param placement where scan pods go — the dedicated pool 0045 §6 requires: {@code nodeSelector},
     *     {@code tolerations} and {@code affinity}, and nothing else, copied into each pod's spec
     * @param cache where the matcher's database generations are kept for scan pods, or {@code null} to copy
     *     each into its pod like any mount
     */
    public record Settings(String namespace, String agent, String helperImage, String defaultUser, Duration startTimeout,
            ScannerLimits limits, ObjectNode placement, MatcherCache cache) {

        /** Without a matcher cache: every mount is copied. */
        public Settings(String namespace, String agent, String helperImage, String defaultUser, Duration startTimeout,
                ScannerLimits limits, ObjectNode placement) {
            this(namespace, agent, helperImage, defaultUser, startTimeout, limits, placement, null);
        }

        /** What placement may set: where the pod goes, never what it may do. */
        static final java.util.Set<String> PLACEMENT = java.util.Set.of("nodeSelector", "tolerations", "affinity");

        public Settings {
            placement = placement == null ? new com.fasterxml.jackson.databind.ObjectMapper().createObjectNode() : placement.deepCopy();
            for (String field : (Iterable<String>) placement::fieldNames) {
                if (!PLACEMENT.contains(field)) {
                    throw new IllegalArgumentException("The scan pods' placement sets nodeSelector, tolerations and "
                            + "affinity, not \"" + field + "\".");
                }
            }
            agent = ScanPods.labelValue(agent);
        }
    }

    /**
     * **The matcher's database, kept once per generation where scan pods can mount it** (decision 0045 §7).
     *
     * <p>The database is some 3 GB, and copied into each matcher pod like any mount it would cross the API
     * server at every scan. A volume of the agent's cannot be shared: a claim belongs to one namespace, and scan
     * pods live in another. So the claim is in the scans' namespace, and each generation — a directory
     * {@code VulnerabilityDatabase} publishes once and never changes — is copied onto it the first time a pod
     * needs it, then mounted read-only by every matcher after.
     *
     * @param claim the ReadWriteOnce claim in the scans' namespace
     * @param generations the agent's own {@code generations} directory: a read-only mount of one of its entries
     *     is served from the cache
     * @param node the agent's node: every pod mounting the claim goes there, since the claim attaches to one
     */
    public record MatcherCache(String claim, Path generations, String node) {

        public MatcherCache {
            generations = generations.toAbsolutePath().normalize();
        }
    }

    /** A generation's name, as {@code VulnerabilityDatabase} writes it: nothing a shell or a path could misread. */
    private static final java.util.regex.Pattern GENERATION = java.util.regex.Pattern.compile("[0-9a-z][0-9a-z-]{0,63}");

    /** The static busybox the wrapper runs: musl, so it needs nothing of the scanner's image. */
    public static final String HELPER_IMAGE =
            "busybox@sha256:5cec3fc171c87218698e85a52af7087de727372aae264a787b8112901a5b0092";

    private static final Duration POLL = Duration.ofMillis(500);
    /** A metadata answer, a df: small. */
    private static final long SMALL = 64 * 1024;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final KubernetesApi api;
    private final Settings settings;
    /** One seeding at a time: two matcher pods must not both copy the same generation onto the volume. */
    private final java.util.concurrent.locks.ReentrantLock seeding = new java.util.concurrent.locks.ReentrantLock();

    public KubernetesExecutor(KubernetesApi api, Settings settings) {
        this.api = api;
        this.settings = settings;
    }

    @Override
    public long outputBytes() {
        return settings.limits().outputBytes();
    }

    @Override
    public Duration scannerTimeout() {
        return settings.limits().timeout();
    }

    /** Can this agent's service account reach its namespace? Asked before a scan is claimed. */
    @Override
    public boolean isAvailable() {
        try {
            api.pods(settings.namespace(), ScanPods.LABEL_AGENT + "=" + settings.agent());
            return true;
        } catch (RuntimeException unreachable) {
            return false;
        }
    }

    /** Deletes every pod this agent left: a crash between a pod's creation and its deletion. */
    public void sweep() {
        api.deletePods(settings.namespace(), ScanPods.LABEL_AGENT + "=" + settings.agent());
    }

    /**
     * **Does the scans' namespace refuse a privileged pod?** (decision 0045 §3) Asked of the API server with a
     * dry run of the widest pod there is — privileged, root, the host's filesystem, its network and PIDs — since
     * the Role cannot read the namespace's labels. Only Pod Security's own refusal counts: a pod admitted, or
     * refused for any other reason, says nothing about the ceiling, and a compromised agent would start that pod
     * for real (the security review of 2026-10-26, M1).
     *
     * @return {@link Isolation#ENFORCED} when Pod Security refused it, {@link Isolation#NOT_ENFORCED} when it
     *     would have been admitted
     * @throws KubernetesException for any other answer: an unknown
     */
    public Isolation podSecurity() {
        com.fasterxml.jackson.databind.node.ObjectNode pod = new com.fasterxml.jackson.databind.ObjectMapper().createObjectNode();
        pod.put("apiVersion", "v1").put("kind", "Pod");
        pod.putObject("metadata").put("name", "vs-pod-security-probe");
        com.fasterxml.jackson.databind.node.ObjectNode spec = pod.putObject("spec");
        // Everything else a scan pod carries — its pool's placement, no token — so that the chart's admission
        // policy, which refuses a pod without them, has nothing to refuse: only Pod Security may answer, or the
        // answer proves nothing about it. On k3s 1.34 Pod Security answers first whatever the pod (measured: the
        // test still passes without these lines); they make the answer independent of the admission order.
        settings.placement().properties().forEach(field -> spec.set(field.getKey(), field.getValue().deepCopy()));
        spec.put("automountServiceAccountToken", false);
        spec.put("hostNetwork", true).put("hostPID", true);
        spec.putArray("volumes").addObject().put("name", "host").putObject("hostPath").put("path", "/");
        com.fasterxml.jackson.databind.node.ObjectNode container = spec.putArray("containers").addObject();
        container.put("name", "probe").put("image", settings.helperImage());
        container.putObject("securityContext").put("privileged", true).put("runAsUser", 0);
        container.putArray("volumeMounts").addObject().put("name", "host").put("mountPath", "/host");
        try {
            api.createPodDryRun(settings.namespace(), pod);
            return Isolation.NOT_ENFORCED;
        } catch (KubernetesException refused) {
            if (refused.status() == 403 && refused.getMessage().contains("PodSecurity")) {
                return Isolation.ENFORCED;
            }
            throw refused;
        }
    }

    /** What a probe found: whether a scan pod is cut off from the address it tried. */
    public enum Isolation { ENFORCED, NOT_ENFORCED }

    /**
     * Runs a scan pod — offline, or {@code online} as the steps that need the network are — that tries to
     * open a TCP connection to {@code host:port}, and says whether it could (decision 0045 §5).
     *
     * <p><b>A NetworkPolicy the CNI does not enforce is accepted and ignored</b>, and nothing on the API
     * says so: the only proof that a scan pod is cut off is a scan pod that tried and failed. The target is
     * the API server's own address, which every pod of a cluster reaches unless a policy stops it, and an
     * address rather than a name, so a failure is a refusal and not a lookup that did not resolve. The pod
     * goes through {@link #run} like any scanner: its labels, its placement, its namespace's policies.
     *
     * @throws com.asmolabs.vectispire.common.scanning.ScannerFailureException when the probe itself did not
     *     run, or said something else — an unknown, which proves nothing either way
     */
    public Isolation probe(String host, int port, boolean online) {
        if (!host.matches("[0-9A-Fa-f.:]+") || port <= 0 || port > 65535) {
            throw new IllegalArgumentException("The probe's target is an address and a port, not \"" + host + ":" + port + "\".");
        }
        // **A connection on the pod's own loopback first, which must succeed**: without it, an image whose `nc`
        // is missing or broken would fail every connection and read as "blocked" (review of 2026-10-26, L1).
        ContainerRun probe = ContainerRun.of(settings.helperImage(), List.of("sh", "-c",
                "nc -l -p 7777 -s 127.0.0.1 >/dev/null 2>&1 & sleep 1; "
                        + "if ! nc -w 2 127.0.0.1 7777 </dev/null >/dev/null 2>&1; then echo NO-CONTROL; exit 0; fi; "
                        + "if nc -w 5 " + host + " " + port + " </dev/null >/dev/null 2>&1; then echo REACHED; else echo BLOCKED; fi"),
                List.of(), "network probe").withEntrypoint(List.of()).withTimeout(Duration.ofMinutes(1));
        String said = run(online ? probe.withNetwork() : probe).stdout().strip();
        return switch (said) {
            case "BLOCKED" -> Isolation.ENFORCED;
            case "REACHED" -> Isolation.NOT_ENFORCED;
            default -> throw ScannerFailureException.of("network probe", "The probe said \"" + said
                    + "\", which is neither: whether scan pods are cut off is unknown.");
        };
    }

    /**
     * **The ceiling on an image target's archive**, which comes back from the copier's pod like any file a step
     * wrote — but an image runs to gigabytes where a report stays under the output ceiling. Past it the step fails.
     */
    static final long IMAGE_ARCHIVE_BYTES = 8L * 1024 * 1024 * 1024;

    /** A platform as a registry names one: {@code os/arch[/variant]}. */
    private static final java.util.regex.Pattern PLATFORM = java.util.regex.Pattern.compile("[a-z0-9]+/[a-z0-9_]+(/[a-z0-9]+)?");

    /**
     * **Copies an image target into {@code destination}, as an archive of the format a Docker daemon exports**
     * (decision 0045 §8): the pinned crane, in a pod of its own with the network, pulls {@code reference} for
     * {@code platform} into an empty directory, which comes back like any step's written files. The cataloguer then
     * reads the same kind of archive it reads on Docker, offline — a parser of hostile metadata is never handed the
     * network or a registry.
     *
     * <p><b>Anonymously.</b> No registry credential is held here ({@link #registryAccessFor}): a private image fails
     * the step, and its inventory is absent — never an empty one.
     */
    @Override
    public void exportImage(String reference, String platform, Path destination) {
        String label = "image copy (" + reference + ")";
        // Arguments in exec form, so no shell reads them; but crane would read a leading dash as an option.
        if (reference.isBlank() || reference.startsWith("-") || reference.chars().anyMatch(Character::isWhitespace)) {
            throw ScannerFailureException.of(label, "\"" + reference + "\" is not an image reference.");
        }
        if (!PLATFORM.matcher(platform).matches()) {
            throw ScannerFailureException.of(label, "\"" + platform + "\" is not a platform: os/arch[/variant].");
        }
        Path scratch;
        try {
            scratch = Files.createTempDirectory(destination.toAbsolutePath().getParent(), ".image-copy-");
        } catch (IOException unwritable) {
            throw ScannerFailureException.of(label, "No directory to copy the image into: " + unwritable.getMessage());
        }
        try {
            String archive = "image.tar";
            ContainerRun copy = ContainerRun.of(ScannerImages.CRANE,
                            List.of("pull", "--platform", platform, reference, "/out/" + archive),
                            List.of(ContainerRun.Mount.writable(scratch.toString(), "/out")), label)
                    .withNetwork()
                    .runningAsOwnerOf(scratch)
                    .withEntrypoint(ScannerImages.CRANE_ENTRYPOINT);
            ContainerResult copied = run(copy, IMAGE_ARCHIVE_BYTES);
            if (copied.exitCode() != 0) {
                throw ScannerFailureException.exited(label, copied.exitCode(), copied.stderr());
            }
            Path written = scratch.resolve(archive);
            if (!Files.isRegularFile(written, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
                throw ScannerFailureException.of(label, "crane exited 0 and wrote no archive: the image was not copied.");
            }
            Files.move(written, destination, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException unmovable) {
            throw ScannerFailureException.of(label, "The image's archive could not be put in place: " + unmovable.getMessage());
        } finally {
            try (java.util.stream.Stream<Path> left = Files.walk(scratch)) {
                left.sorted(java.util.Comparator.reverseOrder()).forEach(path -> path.toFile().delete());
            } catch (IOException ignored) {
                // The workspace's removal takes what is left.
            }
        }
    }

    /**
     * None held: the cluster pulls the scanners' images with its own credentials, which the agent never
     * sees, and a tool that reads a registry reads it anonymously.
     */
    @Override
    public ContainerRunner.RegistryAccess registryAccessFor(String reference) {
        return new ContainerRunner.RegistryAccess(ContainerRunner.registryOf(reference), false);
    }

    @Override
    public ContainerResult run(ContainerRun request) {
        return run(request, outputBytes());
    }

    /**
     * @param writtenCeiling what a writable mount may bring back, in bytes: the output ceiling for a scanner, an
     *     image's for the copier
     */
    private ContainerResult run(ContainerRun request, long writtenCeiling) {
        String label = request.label();
        Duration timeout = request.timeout() == null ? settings.limits().timeout() : request.timeout();
        if (request.output() != null && request.user() == null) {
            throw new IllegalArgumentException("A bounded output needs the user it belongs to.");
        }
        long[] owner = owner(request.user() == null ? settings.defaultUser() : request.user(), label);
        List<ScanPods.MountSource> sources = new ArrayList<>();
        for (ContainerRun.Mount mount : request.mounts()) {
            Path source = Path.of(mount.source());
            if (!Files.exists(source)) {
                throw ScannerFailureException.of(label, "Its mount " + mount.source() + " does not exist.");
            }
            if (cachedGeneration(mount, source)) {
                sources.add(new ScanPods.MountSource(true, source.getFileName().toString()));
                continue;
            }
            String name = MountArchives.nameOf(source);
            if (!mount.readOnly() && !name.isEmpty()) {
                throw new IllegalArgumentException("A writable mount is a directory here: " + mount.source() + ".");
            }
            sources.add(new ScanPods.MountSource(false, name));
        }

        String slug = ScanPods.labelValue(label).replaceAll("[^a-z0-9-]", "-");
        slug = slug.substring(0, Math.min(40, slug.length())).replaceAll("^-+|-+$", "");
        byte[] suffix = new byte[5];
        RANDOM.nextBytes(suffix);
        String pod = "vs-" + slug + "-" + HexFormat.of().formatHex(suffix);
        try {
            api.createPod(settings.namespace(),
                    ScanPods.pod(pod, request, settings, owner[0], owner[1], sources,
                            copiedBytes(request, sources) + Math.max(0, writtenCeiling - outputBytes()), timeout));
        } catch (KubernetesException refused) {
            throw ScannerFailureException.of(label, "Its pod could not be created: " + refused.getMessage());
        }
        try {
            awaitReceiving(pod, label);
            for (int i = 0; i < request.mounts().size(); i++) {
                Path source = Path.of(request.mounts().get(i).source());
                if (sources.get(i).cached()) {
                    seed(pod, source, label);
                } else {
                    copyIn(pod, i, source, label);
                }
            }
            exec(pod, ScanPods.RECEIVE, List.of("touch", ScanPods.RECEIVED), SMALL, label);

            JsonNode terminated = awaitScanner(pod, timeout, label);
            if ("OOMKilled".equals(terminated.path("reason").asText())) {
                throw ScannerFailureException.of(label, "Scanner \"" + label + "\" ran out of memory (its limit is "
                        + settings.limits().memory() / (1024 * 1024) + " MiB) and was stopped.");
            }
            int exitCode = terminated.path("exitCode").asInt();

            String stdout;
            String stderr;
            if (request.entrypoint() != null) {
                KubernetesApi.ExecResult out = exec(pod, ScanPods.HOLDER, List.of("cat", ScanPods.STDOUT), outputBytes(), label);
                if (out.overCeiling()) {
                    throw ScannerFailureException.of(label, "Scanner \"" + label + "\" wrote more than " + outputBytes()
                            + " bytes of output; it was stopped and its output discarded.");
                }
                KubernetesApi.ExecResult err = exec(pod, ScanPods.HOLDER, List.of("head", "-c",
                        String.valueOf(ContainerRunner.STDERR_BYTES), ScanPods.STDERR), ContainerRunner.STDERR_BYTES, label);
                if (out.exitCode() != 0 || err.exitCode() != 0) {
                    // An output that could not be read is absent, not empty (0007; review of 2026-10-26, L5).
                    throw ScannerFailureException.of(label, "Scanner \"" + label + "\"'s output could not be read back: "
                            + excerpt(out.stderr() + err.stderr()));
                }
                stdout = new String(out.stdout(), StandardCharsets.UTF_8);
                stderr = new String(err.stdout(), StandardCharsets.UTF_8);
            } else {
                // No entrypoint declared, so no wrapper: the tool wrote to its log, read as a diagnostic only.
                // Its standard output is not captured, and a caller parsing it reads an absent report.
                stdout = "";
                stderr = log(pod, label);
            }

            Optional<CollectedOutput> collected = request.output() == null
                    ? Optional.empty()
                    : Optional.of(collect(pod, request.output(), label));
            for (int i = 0; i < request.mounts().size(); i++) {
                ContainerRun.Mount mount = request.mounts().get(i);
                if (!mount.readOnly()) {
                    copyBack(pod, i, Path.of(mount.source()), label, writtenCeiling);
                }
            }
            return new ContainerResult(stdout, stderr, exitCode, collected);
        } catch (KubernetesException failed) {
            throw ScannerFailureException.of(label, "Kubernetes failed it: " + failed.getMessage());
        } finally {
            try {
                api.deletePod(settings.namespace(), pod);
            } catch (RuntimeException left) {
                // The sweep at the next start removes it; the run's own outcome is what matters here.
            }
        }
    }

    /** What the copied mounts hold, in bytes, links not followed: what the work volume receives. */
    private static long copiedBytes(ContainerRun request, List<ScanPods.MountSource> sources) {
        long total = 0;
        for (int i = 0; i < request.mounts().size(); i++) {
            if (sources.get(i).cached()) {
                continue;
            }
            try (java.util.stream.Stream<Path> files = Files.walk(Path.of(request.mounts().get(i).source()))) {
                total += files.filter(file -> Files.isRegularFile(file, java.nio.file.LinkOption.NOFOLLOW_LINKS))
                        .mapToLong(file -> {
                            try {
                                return Files.size(file);
                            } catch (IOException unreadable) {
                                return 0;
                            }
                        }).sum();
            } catch (IOException unreadable) {
                // Counted as nothing: the copy that follows reads the same tree and fails on it, by name.
            }
        }
        return total;
    }

    /** A read-only mount of one of the agent's database generations, with a cache to serve it from. */
    private boolean cachedGeneration(ContainerRun.Mount mount, Path source) {
        MatcherCache cache = settings.cache();
        if (cache == null || !mount.readOnly()) {
            return false;
        }
        Path absolute = source.toAbsolutePath().normalize();
        return cache.generations().equals(absolute.getParent())
                && Files.isDirectory(absolute, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                && GENERATION.matcher(absolute.getFileName().toString()).matches();
    }

    /**
     * Puts {@code generation} on the cache volume unless it is there already, through the pod's receiving
     * container, then removes the generations the agent no longer holds.
     *
     * <p><b>Complete or absent.</b> It is received into a directory of its own, renamed into place, and only
     * then marked {@code <name>.complete}; a generation without its mark — an agent that died mid-copy — is
     * removed and copied again. Names are checked against what {@code VulnerabilityDatabase} writes before
     * they reach a shell.
     */
    private void seed(String pod, Path generation, String label) {
        String name = generation.getFileName().toString();
        String root = ScanPods.CACHE + "/" + ScanPods.GENERATIONS;
        seeding.lock();
        try {
            if (exec(pod, ScanPods.RECEIVE, List.of("test", "-f", root + "/" + name + ".complete"), SMALL, label).exitCode() != 0) {
                String partial = root + "/." + name + ".partial";
                AtomicReference<IOException> unreadable = new AtomicReference<>();
                PipedInputStream in = new PipedInputStream(1024 * 1024);
                Thread writer;
                try {
                    PipedOutputStream out = new PipedOutputStream(in);
                    writer = Thread.ofVirtual().start(() -> {
                        try (OutputStream closing = out) {
                            MountArchives.write(generation, closing);
                        } catch (IOException failed) {
                            unreadable.set(failed);
                        }
                    });
                } catch (IOException impossible) {
                    throw new IllegalStateException(impossible);
                }
                KubernetesApi.ExecResult received;
                try (InputStream reading = in) {
                    received = api.exec(settings.namespace(), pod, ScanPods.RECEIVE, List.of("sh", "-c",
                            "rm -rf " + root + "/" + name + " " + partial + " && mkdir -p " + partial + " && tar -x -C " + partial),
                            reading, SMALL, settings.startTimeout());
                } catch (IOException closing) {
                    throw ScannerFailureException.of(label, "The matcher's database could not be sent: " + closing.getMessage());
                }
                join(writer);
                if (unreadable.get() != null || received.exitCode() != 0) {
                    throw ScannerFailureException.of(label, "The matcher's database could not be put on its volume: "
                            + (unreadable.get() != null ? unreadable.get().getMessage() : excerpt(received.stderr())));
                }
                if (exec(pod, ScanPods.RECEIVE, List.of("sh", "-c", "mv " + partial + " " + root + "/" + name
                        + " && touch " + root + "/" + name + ".complete"), SMALL, label).exitCode() != 0) {
                    throw ScannerFailureException.of(label, "The matcher's database could not be marked complete on its volume.");
                }
            }
            prune(pod, name, label);
        } finally {
            seeding.unlock();
        }
    }

    /** Removes from the volume every generation the agent no longer holds: the volume follows the agent's cache. */
    private void prune(String pod, String using, String label) {
        java.util.Set<String> held = new java.util.TreeSet<>(List.of(using));
        try (java.util.stream.Stream<Path> entries = Files.list(settings.cache().generations())) {
            entries.map(entry -> entry.getFileName().toString()).filter(entry -> GENERATION.matcher(entry).matches())
                    .forEach(held::add);
        } catch (IOException unreadable) {
            return; // Nothing removed: a generation kept too long costs space, one removed too early a scan.
        }
        String root = ScanPods.CACHE + "/" + ScanPods.GENERATIONS;
        StringBuilder script = new StringBuilder("cd " + root + " && for entry in * .*.partial; do case \"$entry\" in");
        for (String generation : held) {
            script.append(" ").append(generation).append("|").append(generation).append(".complete) ;;");
        }
        script.append(" '*'|'.*.partial') ;; *) rm -rf \"$entry\" ;; esac; done");
        exec(pod, ScanPods.RECEIVE, List.of("sh", "-c", script.toString()), SMALL, label);
    }

    /** {@code uid:gid}, numeric and not root: the namespace refuses root, and a name means nothing in a pod. */
    private static long[] owner(String user, String label) {
        String[] parts = user.split(":", 2);
        try {
            long uid = Long.parseLong(parts[0]);
            long gid = parts.length == 2 ? Long.parseLong(parts[1]) : uid;
            if (uid <= 0 || gid < 0) {
                throw ScannerFailureException.of(label, "It would run as root, which a scan pod never does.");
            }
            return new long[] {uid, gid};
        } catch (NumberFormatException named) {
            throw ScannerFailureException.of(label, "It runs as \"" + user + "\", and a scan pod runs as a numeric uid:gid.");
        }
    }

    private void awaitReceiving(String pod, String label) {
        long deadline = System.nanoTime() + settings.startTimeout().toNanos();
        JsonNode last = null;
        while (System.nanoTime() < deadline) {
            last = api.pod(settings.namespace(), pod).orElseThrow(() -> ScannerFailureException.of(label,
                    "Its pod was deleted before the scanner started."));
            Optional<String> failure = ScanPods.failure(last);
            if (failure.isPresent()) {
                throw ScannerFailureException.of(label, "Its pod could not run: " + failure.get());
            }
            if (ScanPods.receiving(last)) {
                return;
            }
            pause();
        }
        throw ScannerFailureException.of(label, "Its pod was not ready to receive the workspace within "
                + settings.startTimeout().toSeconds() + "s (" + (last == null ? "never read" : ScanPods.pending(last)) + ").");
    }

    private JsonNode awaitScanner(String pod, Duration timeout, String label) {
        long deadline = System.nanoTime() + timeout.toNanos();
        while (System.nanoTime() < deadline) {
            JsonNode state = api.pod(settings.namespace(), pod).orElseThrow(() -> ScannerFailureException.of(label,
                    "Its pod was deleted while the scanner ran."));
            Optional<JsonNode> terminated = ScanPods.scannerTerminated(state);
            if (terminated.isPresent()) {
                return terminated.get();
            }
            Optional<String> failure = ScanPods.failure(state);
            if (failure.isPresent()) {
                throw ScannerFailureException.of(label, "Its pod could not run: " + failure.get());
            }
            pause();
        }
        // Deleted in the caller's finally, which stops it: abandoning the wait alone would leave it running.
        throw ScannerFailureException.timedOut(label, timeout);
    }

    private void copyIn(String pod, int index, Path source, String label) {
        PipedInputStream in = new PipedInputStream(1024 * 1024);
        AtomicReference<IOException> unreadable = new AtomicReference<>();
        Thread writer;
        try {
            PipedOutputStream out = new PipedOutputStream(in);
            writer = Thread.ofVirtual().start(() -> {
                try (OutputStream closing = out) {
                    MountArchives.write(source, closing);
                } catch (IOException failed) {
                    unreadable.set(failed);
                }
            });
        } catch (IOException impossible) {
            throw new IllegalStateException(impossible);
        }
        String directory = ScanPods.WORK + "/m" + index;
        KubernetesApi.ExecResult result;
        try (InputStream reading = in) {
            result = api.exec(settings.namespace(), pod, ScanPods.RECEIVE,
                    List.of("sh", "-c", "mkdir -p " + directory + " && tar -x -C " + directory), reading, SMALL,
                    settings.startTimeout());
        } catch (IOException closing) {
            throw ScannerFailureException.of(label, "Its workspace could not be sent: " + closing.getMessage());
        }
        join(writer);
        if (unreadable.get() != null) {
            throw ScannerFailureException.of(label, "Its workspace could not be read: " + unreadable.get().getMessage());
        }
        if (result.exitCode() != 0) {
            throw ScannerFailureException.of(label, "Its workspace could not be received (tar exited "
                    + result.exitCode() + "): " + excerpt(result.stderr()));
        }
    }

    /** What the scanner wrote into a writable mount, and nothing else: see {@link MountArchives}. */
    private void copyBack(String pod, int index, Path destination, String label, long ceiling) {
        String directory = ScanPods.WORK + "/m" + index;
        // tar refuses an empty list, so nothing written sends nothing. **A name with a line break is refused
        // before the list is built**: the list is one name per line, and such a name would make the holder archive
        // a path the scanner chose (review of 2026-10-26, L4).
        String script = "cd " + directory + " && nl=$(printf '\\nx') && nl=${nl%x} && "
                + "if [ -n \"$(find . -name \"*$nl*\")\" ]; then echo 'a name with a line break' >&2; exit 3; fi && "
                + "if [ -n \"$(find . -type f -mtime -1)\" ]; then find . -type f -mtime -1 | tar -c -T -; fi";
        Path received = null;
        try {
            received = Files.createTempFile("vectispire-written", ".tar");
            KubernetesApi.ExecResult result;
            try (OutputStream out = Files.newOutputStream(received)) {
                result = api.exec(settings.namespace(), pod, ScanPods.HOLDER, List.of("sh", "-c", script), null, out,
                        ceiling, settings.startTimeout());
            }
            if (result.overCeiling()) {
                throw ScannerFailureException.of(label, "It wrote more than " + ceiling + " bytes into its workspace.");
            }
            if (result.exitCode() != 0) {
                throw ScannerFailureException.of(label, "What it wrote could not be read back (exit "
                        + result.exitCode() + "): " + excerpt(result.stderr()));
            }
            if (Files.size(received) > 0) {
                try (InputStream in = Files.newInputStream(received)) {
                    MountArchives.extractWritten(in, destination, ceiling);
                }
            }
        } catch (IOException refused) {
            throw ScannerFailureException.of(label, "What it wrote was not brought back: " + refused.getMessage());
        } finally {
            if (received != null) {
                try {
                    Files.deleteIfExists(received);
                } catch (IOException ignored) {
                    // A temporary file; the next start's temporary directory is not ours to clean.
                }
            }
        }
    }

    /**
     * The bounded output's file and what the kernel says of its directory, read from the holder — the same
     * answer {@link ContainerRunner} gives, so the plugins read it the same way.
     */
    private CollectedOutput collect(String pod, ContainerRun.BoundedOutput bounded, String label) {
        String file = bounded.target() + "/" + bounded.file();
        long ceiling = Math.min(bounded.bytes(), outputBytes());
        String probe = "df -P -k " + bounded.target() + "; df -P -i " + bounded.target() + "; f=" + file
                + "; if [ -L \"$f\" ]; then echo kind=other; elif [ ! -e \"$f\" ]; then echo kind=missing; "
                + "elif [ ! -f \"$f\" ]; then echo kind=other; else echo kind=file size=$(wc -c < \"$f\"); fi";
        String answer = new String(exec(pod, ScanPods.HOLDER, List.of("sh", "-c", probe), SMALL, label).stdout(),
                StandardCharsets.UTF_8);
        OutputFile read;
        if (answer.contains("kind=missing")) {
            read = new OutputFile.Missing();
        } else if (!answer.contains("kind=file size=")) {
            read = new OutputFile.NotRegular();
        } else {
            long size = Long.parseLong(answer.substring(answer.indexOf("kind=file size=") + 15).strip());
            if (size > ceiling) {
                read = new OutputFile.TooLarge(size);
            } else {
                KubernetesApi.ExecResult content = exec(pod, ScanPods.HOLDER, List.of("cat", file), ceiling, label);
                read = content.overCeiling() ? new OutputFile.TooLarge(ceiling + 1) : new OutputFile.Read(content.stdout());
            }
        }
        return CollectedOutput.measured(bounded, answer, read).orElseThrow(() -> ScannerFailureException.of(label,
                "Its output directory could not be measured, so whether a write was refused is unknown; the report "
                        + "is not believed."));
    }

    private KubernetesApi.ExecResult exec(String pod, String container, List<String> command, long ceiling, String label) {
        KubernetesApi.ExecResult result = api.exec(settings.namespace(), pod, container, command, null, ceiling,
                settings.startTimeout());
        if (result.overCeiling() && ceiling == SMALL) {
            throw ScannerFailureException.of(label, "Its pod answered more than expected to " + command.getFirst() + ".");
        }
        return result;
    }

    private String log(String pod, String label) {
        try {
            return api.log(settings.namespace(), pod, ScanPods.SCANNER, ContainerRunner.STDERR_BYTES);
        } catch (KubernetesException unreadable) {
            return "(its log could not be read: " + unreadable.getMessage() + ")";
        }
    }

    private static String excerpt(String text) {
        return text.length() > 500 ? text.substring(0, 500) + "…" : text;
    }

    private static void join(Thread thread) {
        try {
            thread.join(Duration.ofMinutes(1));
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        }
    }

    private static void pause() {
        try {
            TimeUnit.MILLISECONDS.sleep(POLL.toMillis());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw ScannerFailureException.of("scan", "Interrupted while waiting for its pod.");
        }
    }
}
