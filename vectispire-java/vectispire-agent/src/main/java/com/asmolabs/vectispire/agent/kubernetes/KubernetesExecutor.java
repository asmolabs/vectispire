package com.asmolabs.vectispire.agent.kubernetes;

import com.asmolabs.vectispire.common.scanning.ContainerExecutor;
import com.asmolabs.vectispire.common.scanning.ContainerRun;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import com.asmolabs.vectispire.common.scanning.ContainerRunner.CollectedOutput;
import com.asmolabs.vectispire.common.scanning.ContainerRunner.ContainerResult;
import com.asmolabs.vectispire.common.scanning.ContainerRunner.OutputFile;
import com.asmolabs.vectispire.common.scanning.ScannerFailureException;
import com.asmolabs.vectispire.common.scanning.ScannerLimits;
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
     */
    public record Settings(String namespace, String agent, String helperImage, String defaultUser, Duration startTimeout,
            ScannerLimits limits, ObjectNode placement) {

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

    /** The static busybox the wrapper runs: musl, so it needs nothing of the scanner's image. */
    public static final String HELPER_IMAGE =
            "busybox@sha256:5cec3fc171c87218698e85a52af7087de727372aae264a787b8112901a5b0092";

    private static final Duration POLL = Duration.ofMillis(500);
    /** A metadata answer, a df: small. */
    private static final long SMALL = 64 * 1024;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final KubernetesApi api;
    private final Settings settings;

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
     * Not yet: an image target is copied into the workspace by a pinned copy step (0045 §8), which is not
     * built. A failure, so the image's inventory is absent — never an empty one.
     */
    @Override
    public void exportImage(String reference, String platform, Path destination) {
        throw ScannerFailureException.of("image export", "Image targets are not scanned by the Kubernetes executor yet: "
                + "the copy step of decision 0045 §8 is not built. " + reference + " was not examined.");
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
        String label = request.label();
        Duration timeout = request.timeout() == null ? settings.limits().timeout() : request.timeout();
        if (request.output() != null && request.user() == null) {
            throw new IllegalArgumentException("A bounded output needs the user it belongs to.");
        }
        long[] owner = owner(request.user() == null ? settings.defaultUser() : request.user(), label);
        List<String> names = new ArrayList<>();
        for (ContainerRun.Mount mount : request.mounts()) {
            Path source = Path.of(mount.source());
            if (!Files.exists(source)) {
                throw ScannerFailureException.of(label, "Its mount " + mount.source() + " does not exist.");
            }
            String name = MountArchives.nameOf(source);
            if (!mount.readOnly() && !name.isEmpty()) {
                throw new IllegalArgumentException("A writable mount is a directory here: " + mount.source() + ".");
            }
            names.add(name);
        }

        String slug = ScanPods.labelValue(label).replaceAll("[^a-z0-9-]", "-");
        slug = slug.substring(0, Math.min(40, slug.length())).replaceAll("^-+|-+$", "");
        byte[] suffix = new byte[5];
        RANDOM.nextBytes(suffix);
        String pod = "vs-" + slug + "-" + HexFormat.of().formatHex(suffix);
        try {
            api.createPod(settings.namespace(), ScanPods.pod(pod, request, settings, owner[0], owner[1], names, timeout));
        } catch (KubernetesException refused) {
            throw ScannerFailureException.of(label, "Its pod could not be created: " + refused.getMessage());
        }
        try {
            awaitReceiving(pod, label);
            for (int i = 0; i < request.mounts().size(); i++) {
                copyIn(pod, i, Path.of(request.mounts().get(i).source()), label);
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
                stdout = new String(out.stdout(), StandardCharsets.UTF_8);
                stderr = new String(exec(pod, ScanPods.HOLDER, List.of("head", "-c",
                        String.valueOf(ContainerRunner.STDERR_BYTES), ScanPods.STDERR), ContainerRunner.STDERR_BYTES, label)
                        .stdout(), StandardCharsets.UTF_8);
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
                    copyBack(pod, i, Path.of(mount.source()), label);
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
    private void copyBack(String pod, int index, Path destination, String label) {
        String directory = ScanPods.WORK + "/m" + index;
        // tar refuses an empty list, so nothing written sends nothing.
        String script = "cd " + directory + " && if [ -n \"$(find . -type f -mtime -1)\" ]; then "
                + "find . -type f -mtime -1 | tar -c -T -; fi";
        Path received = null;
        try {
            received = Files.createTempFile("vectispire-written", ".tar");
            KubernetesApi.ExecResult result;
            try (OutputStream out = Files.newOutputStream(received)) {
                result = api.exec(settings.namespace(), pod, ScanPods.HOLDER, List.of("sh", "-c", script), null, out,
                        outputBytes(), settings.startTimeout());
            }
            if (result.overCeiling()) {
                throw ScannerFailureException.of(label, "It wrote more than " + outputBytes() + " bytes into its workspace.");
            }
            if (result.exitCode() != 0) {
                throw ScannerFailureException.of(label, "What it wrote could not be read back (exit "
                        + result.exitCode() + "): " + excerpt(result.stderr()));
            }
            if (Files.size(received) > 0) {
                try (InputStream in = Files.newInputStream(received)) {
                    MountArchives.extractWritten(in, destination);
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
