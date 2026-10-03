package com.asmolabs.vectispire.common.scanning;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.async.ResultCallback;
import com.github.dockerjava.api.command.CreateContainerResponse;
import com.github.dockerjava.api.command.WaitContainerResultCallback;
import com.github.dockerjava.api.model.AccessMode;
import com.github.dockerjava.api.model.AuthConfig;
import com.github.dockerjava.api.model.Driver;
import com.github.dockerjava.api.model.Frame;
import com.github.dockerjava.api.model.HostConfig;
import com.github.dockerjava.api.model.Mount;
import com.github.dockerjava.api.model.MountType;
import com.github.dockerjava.api.model.StreamType;
import com.github.dockerjava.api.model.Ulimit;
import com.github.dockerjava.api.model.VolumeOptions;
import com.github.dockerjava.api.model.VolumesFrom;
import com.github.dockerjava.core.DefaultDockerClientConfig;
import com.github.dockerjava.core.DockerClientImpl;
import com.github.dockerjava.httpclient5.ApacheDockerHttpClient;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import javax.net.ssl.SSLContext;

/**
 * Running a scanner container.
 *
 * <p><b>These containers analyse hostile input by definition.</b> See {@link ScannerLimits} for
 * what that costs them.
 *
 * <p><b>None of them sees the Docker socket.</b> The image SBOM step used to mount it, which is
 * equivalent to root on the host: a parsing flaw in the cataloguer — which by definition reads
 * the layers of an image nobody controls — became a full escape. Vectispire now exports the image
 * itself and hands the container a single read-only file. There is no option to mount the
 * socket, and that absence is the design: an option survives, a missing capability does not.
 *
 * <p><b>The two streams are kept apart.</b> One combined output would corrupt the JSON on
 * stdout, and silencing both would lose the scanner's own explanation — the one that ends up in
 * the error an operator reads. So each is collected separately: stdout stays parseable
 * <em>and</em> the reason for the failure survives.
 */
public final class ContainerRunner {

    /** The mark placed on every container Vectispire launches. */
    public static final String SCANNER_LABEL = "dev.vectispire.scanner";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Where a scanner is allowed to write, and how much.
     *
     * <p>The root filesystem is read-only, so this is the whole of it. It is a tmpfs, hence
     * memory: sized so an unpacked image layer set fits and a runaway does not take the host
     * down with it. It is counted against the container's memory limit by the kernel, which is
     * the behaviour wanted — one budget, not two.
     */
    private static final int SCRATCH_MEGABYTES = 512;

    /**
     * A writable {@code HOME}, because several scanner images do not set one.
     *
     * <p>Their default is {@code /} or a path inside the image, and a cache written there
     * against a read-only root fails outright rather than being skipped. Pointed at a tmpfs and
     * exported below, so the failure never arises.
     */
    private static final String SCRATCH_HOME = "/home/scanner";

    /**
     * Where the vulnerability database goes, for the one scanner that has one.
     *
     * <p>Public and named from the mounting side too, because the environment variable set here
     * and the mount declared there have to be the same path. Two constants agreeing by
     * convention would need a test; one constant is the property itself.
     */
    public static final String DATABASE_CACHE_MOUNT = "/cache";

    /**
     * Where a {@link ContainerRun.RegistryLogin} is mounted, read-only, and what {@code DOCKER_CONFIG}
     * names in the tool's environment: the variable every client built on the Docker CLI's
     * configuration reads, cosign's included.
     */
    public static final String REGISTRY_LOGIN_MOUNT = "/trust/registry";

    private final DockerClient docker;
    private final ScannerLimits limits;

    /**
     * The CPU quota this daemon will actually accept, resolved once.
     *
     * <p>Not a field set in the constructor: {@code ContainerRunner} is built while Spring wires
     * the context, and asking a daemon that is not running would turn "no Docker today" into "the
     * application does not start". Resolved on the first run instead, where a missing daemon is
     * already the failure being reported.
     */
    private volatile Long daemonNanoCpus;

    public ContainerRunner() {
        this(defaultClient(), ScannerLimits.DEFAULT);
    }

    public ContainerRunner(ScannerLimits limits) {
        this(defaultClient(), limits);
    }

    /** Package-private: the client type is an implementation detail nothing outside may name. */
    ContainerRunner(DockerClient docker, ScannerLimits limits) {
        this.docker = docker;
        this.limits = limits;
    }

    private static DockerClient defaultClient() {
        return clientAt(resolveDockerHost());
    }

    /**
     * The client of the daemon at {@code host} — blank for the configuration's own — one request per
     * connection: see {@link OneRequestPerConnection}. Package-private so the suite that starts the
     * shipped socket proxy builds exactly this one.
     */
    static DockerClient clientAt(String host) {
        DefaultDockerClientConfig.Builder builder = DefaultDockerClientConfig.createDefaultConfigBuilder();
        if (host != null && !host.isBlank()) {
            builder.withDockerHost(host);
        }
        return clientOf(builder.build());
    }

    /**
     * The client of the daemon {@code config} names, over TLS when the configuration asks for it.
     *
     * <p><b>The transport is handed the configuration's TLS settings, and it was not.</b> The
     * configuration reads {@code DOCKER_TLS_VERIFY} and {@code DOCKER_CERT_PATH}; the transport was
     * built from the host alone, and docker-java speaks {@code https} to a {@code tcp://} host only
     * when its transport holds an SSL context. A daemon on {@code tcp://…:2376} with client
     * certificates — a remote daemon, the only kind a Kubernetes pod can reach (decision 0038) — was
     * spoken to in plain HTTP, and every call failed.
     *
     * <p><b>Refused, not downgraded, when the certificates are missing.</b> docker-java's directory
     * configuration answers no context at all when {@code ca.pem}, {@code cert.pem} or {@code key.pem}
     * is absent, and the transport then falls back to plain HTTP in silence: an operator who asked for
     * TLS would get a daemon spoken to in the clear. Building the context here, once, makes that a
     * failure that names the files. docker-java registers BouncyCastle as the JVM's last provider while
     * it reads them; last, so it answers only what no provider before it does.
     */
    static DockerClient clientOf(DefaultDockerClientConfig config) {
        ApacheDockerHttpClient.Builder transport = new ApacheDockerHttpClient.Builder().dockerHost(config.getDockerHost());
        com.github.dockerjava.transport.SSLConfig tls = config.getSSLConfig();
        if (tls != null) {
            SSLContext context;
            try {
                context = tls.getSSLContext();
            } catch (GeneralSecurityException unreadable) {
                throw new IllegalStateException("DOCKER_TLS_VERIFY is set, and the certificates under DOCKER_CERT_PATH "
                        + "could not be read: " + unreadable.getMessage(), unreadable);
            }
            if (context == null) {
                throw new IllegalStateException("DOCKER_TLS_VERIFY is set, and DOCKER_CERT_PATH does not hold ca.pem, "
                        + "cert.pem and key.pem; the daemon is not spoken to in the clear instead.");
            }
            transport.sslConfig(() -> context);
        }
        return DockerClientImpl.getInstance(config, new OneRequestPerConnection(transport.build()));
    }

    /**
     * Resolves the Docker or Podman daemon socket.
     * Supports `VECTISPIRE_DOCKER_HOST`, `DOCKER_HOST`, macOS (OrbStack, Docker Desktop, Colima) and Rootless Linux auto-detection.
     */
    public static String resolveDockerHost() {
        String vectispireHost = System.getenv("VECTISPIRE_DOCKER_HOST");
        if (vectispireHost != null && !vectispireHost.isBlank()) {
            return vectispireHost.trim();
        }
        String dockerHost = System.getenv("DOCKER_HOST");
        if (dockerHost != null && !dockerHost.isBlank()) {
            return dockerHost.trim();
        }
        String userHome = System.getProperty("user.home", "");
        if (!userHome.isBlank()) {
            String[] userSockets = {
                "/.orbstack/run/docker.sock",
                "/.docker/run/docker.sock",
                "/.colima/default/docker.sock",
                "/.rd/docker.sock"
            };
            for (String subPath : userSockets) {
                try {
                    Path sock = Path.of(userHome, subPath);
                    if (Files.exists(sock)) {
                        return "unix://" + sock.toRealPath().toString();
                    }
                } catch (Exception ignored) {
                }
            }
        }
        String xdgRuntimeDir = System.getenv("XDG_RUNTIME_DIR");
        if (xdgRuntimeDir != null && !xdgRuntimeDir.isBlank()) {
            try {
                Path podmanSock = Path.of(xdgRuntimeDir, "podman", "podman.sock");
                if (Files.exists(podmanSock)) {
                    return "unix://" + podmanSock.toRealPath().toString();
                }
                Path dockerSock = Path.of(xdgRuntimeDir, "docker.sock");
                if (Files.exists(dockerSock)) {
                    return "unix://" + dockerSock.toRealPath().toString();
                }
            } catch (Exception ignored) {
                // Fall back to default
            }
        }
        try {
            Path varRun = Path.of("/var/run/docker.sock");
            if (Files.exists(varRun)) {
                return "unix://" + varRun.toRealPath().toString();
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    /**
     * The ceiling on what a scanner may hand back, in bytes — its standard output here, and the
     * report file a plugin writes, which is the same output by another route and gets the same bound.
     */
    public long outputBytes() {
        return limits.outputBytes();
    }

    /** How long a scanner may run before it is stopped — what a scan that started can still take. */
    public Duration scannerTimeout() {
        return limits.timeout();
    }

    /** Is the daemon reachable? Checked before claiming a scan rather than in the middle of one. */
    public boolean isAvailable() {
        try {
            docker.pingCmd().exec();
            return true;
        } catch (RuntimeException unreachable) {
            return false;
        }
    }

    /**
     * Pulls an image and writes it out as a local archive.
     *
     * <p><b>This is what replaces the Docker socket mounted into the cataloguer.</b> Mounting it
     * is equivalent to handing out root on the host: a parsing flaw in a tool that by definition
     * reads layers nobody controls became a complete escape. Here the only process talking to
     * the daemon is Vectispire, and the scanner sees a file, mounted read-only, with the network
     * cut.
     *
     * <p>{@code platform} is <b>mandatory on the pull</b>: without it the daemon returns the
     * <em>host's</em> architecture, silently producing the inventory of a variant nobody asked
     * to audit. The resulting archive already carries the right one, so nothing downstream has
     * to specify it again.
     */
    public void exportImage(String reference, String platform, Path destination) {
        try {
            docker.pullImageCmd(reference)
                    .withPlatform(platform)
                    .start()
                    .awaitCompletion();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("interrupted while pulling " + reference, interrupted);
        }

        try (InputStream archive = docker.saveImageCmd(reference).exec()) {
            Files.copy(archive, destination);
        } catch (IOException e) {
            throw new IllegalStateException("could not export " + reference, e);
        }
    }

    /**
     * The CPU quota, clamped to the machine that will honour it.
     *
     * <p><b>The count in {@link ScannerLimits#DEFAULT} is this JVM's, and the container runs on the
     * daemon's host.</b> Those differ whenever Docker Desktop is in the way — a Mac with ten cores
     * behind a VM given four — and the daemon does not quietly round down: it refuses the create
     * with <em>"Range of CPUs is from 0.01 to 4.00, as there are only 4 CPUs available"</em>, and
     * every scan on that machine fails. Asking {@code docker info} is the only way to know, because
     * only the daemon knows.
     *
     * <p>Clamped with {@code min} rather than replaced, so the rule works in both directions: a
     * quota an operator deliberately set lower than the host survives, and one larger than the host
     * can grant comes down to {@linkplain ScannerLimits#allButOne all but one} of the daemon's
     * cores — still leaving the control plane a core to answer a gate call on.
     *
     * <p>If the daemon will not say, the configured value stands. That is not a fallback worth
     * much — a daemon that cannot answer {@code info} is not about to create a container — but it
     * keeps this from being a second way for the same outage to be reported.
     */
    private long acceptableNanoCpus() {
        Long resolved = daemonNanoCpus;
        if (resolved != null) {
            return resolved;
        }
        long quota = limits.nanoCpus();
        try {
            Integer cores = docker.infoCmd().exec().getNCPU();
            if (cores != null && cores > 0) {
                quota = Math.min(quota, ScannerLimits.allButOne(cores));
            }
        } catch (RuntimeException daemonWillNotSay) {
            // Deliberately swallowed: see above. The create that follows reports the real problem.
        }
        daemonNanoCpus = quota;
        return quota;
    }

    /**
     * The closed shape every container Vectispire starts is created in — the tool's and, for a
     * bounded output, its holder's alike.
     */
    private HostConfig closedHostConfig(List<String> binds, boolean network) {
        return HostConfig.newHostConfig()
                .withBinds(binds.stream().map(com.github.dockerjava.api.model.Bind::parse).toList())
                .withNetworkMode(network ? "bridge" : "none")
                .withMemory(limits.memory())
                .withNanoCPUs(acceptableNanoCpus())
                .withPidsLimit(limits.pids())
                .withCapDrop(com.github.dockerjava.api.model.Capability.values())
                .withSecurityOpts(List.of("no-new-privileges"))
                // **The image's own filesystem is not the scanner's to modify.** Everything
                // else here was already closed — no capabilities, no new privileges, no network
                // for most — while the root filesystem stayed writable, so a tool that got
                // compromised mid-scan could drop a binary in it and keep it for the life of
                // the container. Read-only ends that, and it costs nothing: a scanner reads
                // code and writes a report to stdout.
                .withReadonlyRootfs(true)
                // What read-only takes away and every one of these tools needs back. Syft and
                // Grype unpack layers, Semgrep compiles rules, Checkov writes a scratch tree —
                // all of it to `/tmp`, none of it worth keeping. `noexec` is the point of doing
                // it this way rather than leaving the root writable: scratch space that cannot
                // be executed from is not somewhere to stage a payload.
                //
                // `HOME` goes with it because several of these images default it to `/` or to a
                // directory in the image, and a cache write there now fails on a read-only
                // filesystem rather than being silently discarded.
                //
                // **`mode=1777`, because the daemon copies the image's own mode onto the tmpfs.** The
                // matcher's image ships a `/tmp` only root may write, and since the matcher runs as
                // the workspace's owner rather than root, it could not create the listing file of its
                // database check: "unable to create listing temp file: permission denied", then
                // "database does not exist", and every scan's vulnerability matching was absent —
                // measured against the pinned image on 2026-09-27. World-writable with the sticky bit
                // is what a `/tmp` is; `noexec` and `nosuid` stay.
                .withTmpFs(Map.of(
                        "/tmp", "rw,noexec,nosuid,mode=1777,size=" + SCRATCH_MEGABYTES + "m",
                        SCRATCH_HOME, "rw,noexec,nosuid,mode=1777,size=" + SCRATCH_MEGABYTES + "m"))
                // Removed explicitly below rather than by the daemon: an interrupted scan must
                // not leave dead containers accumulating on the machine that scans.
                .withAutoRemove(false);
    }

    /** Created — not started — labelled, with the scratch environment, as {@code user}. */
    private String create(String image, List<String> command, String label, String user, boolean asRoot,
            HostConfig hostConfig, List<String> environment) {
        var create = docker.createContainerCmd(image)
                .withCmd(command)
                // **Labelled, because the machine that scans is not necessarily ours.** An
                // agent runs on a shared host where other containers come and go: with no
                // mark, neither an operator nor an orphan sweep can tell what Vectispire
                // launched from the rest.
                .withLabels(Map.of(SCANNER_LABEL, label))
                // Pointed at the tmpfs mounted above. Set for every scanner rather than for the
                // ones known to need it: the next image added is not going to announce that it
                // caches under `$HOME`, it is going to fail a scan on a read-only filesystem
                // and report having found nothing.
                .withEnv(Stream.concat(Stream.of(
                        "HOME=" + SCRATCH_HOME,
                        "TMPDIR=/tmp",
                        "XDG_CACHE_HOME=" + SCRATCH_HOME + "/.cache",
                        // Set for every container although only the matcher reads it: the
                        // alternative is per-run environment plumbing for one variable, and a
                        // scanner that does not know the name ignores it. The matcher is also
                        // the only one that mounts anything at this path — without the mount
                        // the variable names a directory on a read-only filesystem, which is
                        // the loud failure rather than the quiet one.
                        "GRYPE_DB_CACHE_DIR=" + DATABASE_CACHE_MOUNT,
                        // **The matcher never fetches its database while it matches.** It reads the
                        // generation `VulnerabilityDatabase` downloaded once for the host, mounted
                        // read-only and with no network; left on, it would try to update it on every
                        // scan and fail against the read-only mount. `db update` and `db check`,
                        // which are asked explicitly, are not affected.
                        "GRYPE_DB_AUTO_UPDATE=false",
                        // Nor its own version, which is pinned by digest and asked of nobody.
                        "GRYPE_CHECK_FOR_APP_UPDATE=false"), environment.stream()).toList())
                .withHostConfig(hostConfig);
        if (user != null) {
            create = create.withUser(user);
        } else if (asRoot) {
            create = create.withUser("0:0");
        }
        CreateContainerResponse created = create.exec();
        return created.getId();
    }

    public ContainerResult run(ContainerRun request) {
        Duration timeout = request.timeout() == null ? limits.timeout() : request.timeout();
        ContainerRun.BoundedOutput bounded = request.output();
        if (bounded != null && request.user() == null) {
            // The directory is created owned by this uid:gid, mode 0700: without one it would be
            // root's, and a tool that is not root could not write its report.
            throw new IllegalArgumentException("A bounded output needs the user it belongs to.");
        }
        ensureImagePresent(request.image(), request.label());

        String holder = null;
        String container = null;
        Path login = null;
        Optional<AuthConfig> credentials = Optional.empty();
        try {
            List<String> binds = request.binds();
            List<String> environment = List.of();
            if (request.login() != null) {
                credentials = PullCredentials.of(docker, request.login().reference());
                if (credentials.isPresent()) {
                    login = writeLogin(credentials.get(), request.login(), request.label());
                    binds = Stream.concat(binds.stream(),
                            Stream.of(ContainerRun.Mount.readOnly(login.toString(), REGISTRY_LOGIN_MOUNT).toBind())).toList();
                    environment = List.of("DOCKER_CONFIG=" + REGISTRY_LOGIN_MOUNT);
                }
            }
            HostConfig hostConfig = closedHostConfig(binds, request.network());
            if (bounded != null) {
                ensureImagePresent(bounded.holderImage(), request.label());
                holder = startHolder(bounded, request.user(), request.label(), timeout);
                hostConfig = hostConfig
                        .withVolumesFrom(new VolumesFrom(holder, AccessMode.rw))
                        // **No file larger than the directory**, sparse ones included. tmpfs keeps a
                        // sparse file of any apparent size in a few pages, and the daemon archives the
                        // apparent size: without this, `truncate -s 1T` beside the report would be read
                        // back as a terabyte of zeros. The kernel sends SIGXFSZ past it (exit 153).
                        .withUlimits(List.of(new Ulimit("fsize", bounded.bytes(), bounded.bytes())));
            }
            container = create(request.image(), request.command(), request.label(), request.user(), request.asRoot(),
                    hostConfig, environment);
            docker.startContainerCmd(container).exec();
            int exitCode = waitFor(container, timeout, request.label());

            // **Read after the container has finished, not attached before it starts.** A
            // follow-stream attached to a container that has not started yet completes
            // immediately, on output that does not exist yet — which reads as a scanner that
            // printed nothing, and therefore as "analysed, found nothing". The daemon retains
            // the logs, so collecting them afterwards loses none and races on nothing.
            StreamCollector output = new StreamCollector(limits.outputBytes(), STDERR_BYTES);
            docker.logContainerCmd(container)
                    .withStdOut(true)
                    .withStdErr(true)
                    .withTailAll()
                    .exec(output)
                    .awaitCompletion();
            if (output.overflowed()) {
                // Failed, not truncated: a truncated report is not a smaller report, and a JSON cut
                // short would be refused by the parser anyway, with a less useful message.
                throw ScannerFailureException.of(request.label(), "Scanner \"" + request.label()
                        + "\" wrote more than " + limits.outputBytes()
                        + " bytes of output; it was stopped and its output discarded.");
            }

            Optional<CollectedOutput> collected = bounded == null
                    ? Optional.empty()
                    : Optional.of(collect(holder, bounded, request.label()));
            AuthConfig sent = credentials.orElse(null);
            return new ContainerResult(PullCredentials.redact(output.stdout(), sent),
                    PullCredentials.redact(output.stderr(), sent), exitCode, collected);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new ScannerFailureException(request.label(), "Interrupted while reading the scanner's output.");
        } finally {
            // In a `finally`: a forgotten container holds its workspace, hence the whole clone,
            // and the machine eventually runs out of disk. The tool first, then its holder with
            // its volume — the other order would leave the volume in use and the removal refused.
            remove(container, false);
            remove(holder, true);
            // After the container, which held it open: the credentials outlive the run by nothing.
            PullCredentials.erase(login);
        }
    }

    private static Path writeLogin(AuthConfig credentials, ContainerRun.RegistryLogin login, String label) {
        try {
            return PullCredentials.write(credentials, PullCredentials.registryOf(login.reference()), login.directory());
        } catch (IOException unwritable) {
            // The exception's own message names a path, never the credentials.
            throw ScannerFailureException.of(label, "The registry credentials could not be handed to it: "
                    + unwritable.getMessage());
        }
    }

    /**
     * What this executor holds to read {@code reference}'s registry: the registry as its pulls key it,
     * and whether its Docker configuration carries credentials for it — never the credentials. For a
     * tool's refusal to say which of "none held" and "the ones held were refused" it was.
     */
    public RegistryAccess registryAccessFor(String reference) {
        return new RegistryAccess(PullCredentials.registryOf(reference), PullCredentials.of(docker, reference).isPresent());
    }

    /** @param credentialsHeld whether the pulls of the registry are authenticated */
    public record RegistryAccess(String registry, boolean credentialsHeld) {}

    private void remove(String id, boolean withVolumes) {
        if (id == null) {
            return;
        }
        try {
            docker.removeContainerCmd(id).withForce(true).withRemoveVolumes(withVolumes).exec();
        } catch (RuntimeException alreadyGone) {
            // Nothing to do about it, and nothing worth masking the real error for.
        }
    }

    /**
     * The files a bounded output holds by default. A directory's worth: a report and what a tool leaves
     * beside it. Each inode is kernel memory, and without a bound a tool creating empty files would
     * spend the container's memory where no size limit counts it. A caller that needs fewer says so
     * ({@link ContainerRun.BoundedOutput#inodes}).
     */
    public static final int OUTPUT_INODES = 4096;

    /** How long a holder outlives its tool's timeout if nothing removes it — a crash of this process. */
    private static final Duration HOLDER_GRACE = Duration.ofMinutes(10);

    /**
     * Starts the container that owns a bounded output — see {@link ContainerRun.BoundedOutput}.
     *
     * <p>It sleeps, and nothing else, until it is stopped; then it prints what the kernel says of the
     * directory — {@code df} in bytes and in inodes — and exits, which is the one measurement of
     * "full" that does not guess from what is left in it. It expires on its own after the tool's
     * timeout and a grace, so a crash of this process leaves no holder for ever.
     */
    private String startHolder(ContainerRun.BoundedOutput bounded, String user, String label, Duration timeout) {
        String[] owner = user.split(":", 2);
        if (owner.length != 2 || !owner[0].chars().allMatch(Character::isDigit) || !owner[1].chars().allMatch(Character::isDigit)
                || owner[0].isEmpty() || owner[1].isEmpty()) {
            throw new IllegalArgumentException("A bounded output belongs to a numeric uid:gid, not \"" + user + "\".");
        }
        Mount volume = new Mount()
                .withType(MountType.VOLUME)
                .withTarget(bounded.target())
                // Labelled like the containers, so that a sweep can find a volume a crash left behind.
                .withVolumeOptions(new VolumeOptions().withLabels(Map.of(SCANNER_LABEL, label + " (output)")).withDriverConfig(new Driver()
                        .withName("local")
                        .withOptions(Map.of(
                                "type", "tmpfs",
                                "device", "tmpfs",
                                "o", "size=" + bounded.bytes() + ",nr_inodes=" + bounded.inodes()
                                        + ",uid=" + owner[0] + ",gid=" + owner[1]
                                        + ",mode=0700,noexec,nosuid,nodev"))));
        String report = "df -P -k " + bounded.target() + "; df -P -i " + bounded.target();
        String holder = create(
                bounded.holderImage(),
                List.of("sh", "-c", "trap '" + report + "; exit 0' TERM; sleep "
                        + timeout.plus(HOLDER_GRACE).toSeconds() + " & wait"),
                label + " (output)",
                user,
                false,
                closedHostConfig(List.of(), false).withMounts(List.of(volume)),
                List.of());
        try {
            docker.startContainerCmd(holder).exec();
        } catch (RuntimeException refused) {
            remove(holder, true);
            throw ScannerFailureException.of(label, "Its output directory could not be created: " + refused.getMessage());
        }
        return holder;
    }

    /**
     * Reads the file back from the holder, then stops the holder and reads what the kernel said.
     *
     * <p>In that order: stopping the holder unmounts the tmpfs, and what was in it is gone.
     */
    private CollectedOutput collect(String holder, ContainerRun.BoundedOutput bounded, String label)
            throws InterruptedException {
        OutputFile file;
        try (InputStream tar = docker.copyArchiveFromContainerCmd(holder, bounded.target() + "/" + bounded.file()).exec()) {
            // The smaller of the two ceilings: the directory's own, which a report plugin's manifest sets
            // below what a scanner may hand back, and that one.
            file = OutputArchive.read(tar, bounded.file(), Math.min(bounded.bytes(), limits.outputBytes()));
        } catch (com.github.dockerjava.api.exception.NotFoundException absent) {
            file = new OutputFile.Missing();
        } catch (IOException | RuntimeException unreadable) {
            throw ScannerFailureException.of(label, "Its output could not be read back: " + unreadable.getMessage());
        }

        try {
            docker.stopContainerCmd(holder).withTimeout(10).exec();
        } catch (RuntimeException alreadyStopped) {
            // Measured below or not at all; a holder that is gone printed nothing, and says so there.
        }
        StreamCollector measure = new StreamCollector(64 * 1024, 64 * 1024);
        docker.logContainerCmd(holder).withStdOut(true).withStdErr(true).withTailAll().exec(measure).awaitCompletion();
        return CollectedOutput.measured(bounded, measure.stdout(), file)
                .orElseThrow(() -> ScannerFailureException.of(label, "Its output directory could not be measured, so "
                        + "whether a write was refused is unknown; the report is not believed."));
    }

    /**
     * Pulls the scanner image if the host does not have it.
     *
     * <p><b>The API does not pull, and the original never did either.</b> {@code docker run} on
     * the command line pulls implicitly; {@code createContainer} over the daemon API does not,
     * and nothing pre-pulled the scanner images — not the agent image, not the documentation. On
     * a fresh host the first scan of each type therefore died on a daemon error naming a digest
     * and nothing else, which is unreadable to whoever has to act on it.
     *
     * <p>Inspect first, pull only when absent: pulling on every run would add a registry round
     * trip to every scan for an image that changes when somebody edits a pinned digest.
     */
    private void ensureImagePresent(String image, String label) {
        try {
            docker.inspectImageCmd(image).exec();
            return;
        } catch (com.github.dockerjava.api.exception.NotFoundException absent) {
            // Expected on a fresh host; fall through to the pull.
        }

        try {
            docker.pullImageCmd(image).start().awaitCompletion();
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new ScannerFailureException(label, "Interrupted while fetching the scanner image " + image + ".");
        } catch (RuntimeException failure) {
            throw new ScannerFailureException(
                    label,
                    "The scanner image " + image + " is not on this host and could not be fetched: "
                            + failure.getMessage() + " Pre-pull it, or point the corresponding image setting at a "
                            + "registry this machine can reach.");
        }
    }

    /**
     * Waits for the end, or stops the container.
     *
     * <p>Stopping is necessary and not optional: abandoning the wait would leave the container
     * running indefinitely, consuming its memory and its processes, while Vectispire considers the
     * scan finished.
     */
    private int waitFor(String containerId, Duration timeout, String label) {
        try (WaitContainerResultCallback wait = docker.waitContainerCmd(containerId).start()) {
            return wait.awaitStatusCode(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (RuntimeException | IOException timedOut) {
            try {
                docker.stopContainerCmd(containerId).withTimeout(5).exec();
            } catch (RuntimeException alreadyStopped) {
                // Already gone, which is the outcome we wanted.
            }
            throw ScannerFailureException.timedOut(label, timeout);
        }
    }

    /** @param output what a bounded output held, for a run that had one — see {@link ContainerRun#withBoundedOutput} */
    public record ContainerResult(String stdout, String stderr, int exitCode, Optional<CollectedOutput> output) {

        public ContainerResult {
            output = output == null ? Optional.empty() : output;
        }

        public ContainerResult(String stdout, String stderr, int exitCode) {
            this(stdout, stderr, exitCode, Optional.empty());
        }
    }

    /** The one file read back from a bounded output, as the archive answered it. */
    public sealed interface OutputFile {

        /** The tool wrote no file of that name. */
        record Missing() implements OutputFile {}

        /** A link, a directory, a FIFO — anything but a regular file; not read. */
        record NotRegular() implements OutputFile {}

        /** Larger than its directory's ceiling or the scanner output ceiling, whichever is smaller; not read. */
        record TooLarge(long size) implements OutputFile {}

        /** The file's bytes, within the ceiling. */
        record Read(byte[] bytes) implements OutputFile {}
    }

    /**
     * What a bounded output held when its tool exited, in the kernel's words.
     *
     * @param capacity what it could hold, in bytes
     * @param availableBytes what was left, as {@code df} answered it
     * @param availableInodes the files it could still have created
     */
    public record CollectedOutput(long capacity, long availableBytes, long availableInodes, OutputFile file) {

        /** Less than one page left, or no inode: a write was refused, or the next one would have been. */
        public boolean full() {
            return availableBytes < 4096 || availableInodes <= 0;
        }

        /**
         * The holder's {@code df -P -k} and {@code df -P -i} lines for the directory, or empty when
         * either is missing — a holder that died printed nothing, and a guess would be believed.
         */
        static Optional<CollectedOutput> measured(ContainerRun.BoundedOutput bounded, String printed, OutputFile file) {
            // `Filesystem Size Used Available Capacity Mounted-on`: the fourth column, of the two lines
            // naming the directory — the first in KiB, the second in inodes.
            List<Long> available = printed.lines()
                    .map(String::strip)
                    .filter(line -> line.endsWith(" " + bounded.target()))
                    .map(line -> line.split("\\s+"))
                    .filter(columns -> columns.length == 6 && !columns[3].isEmpty()
                            && columns[3].length() < 19 && columns[3].chars().allMatch(Character::isDigit))
                    .map(columns -> Long.parseLong(columns[3]))
                    .toList();
            if (available.size() != 2) {
                return Optional.empty();
            }
            return Optional.of(new CollectedOutput(bounded.bytes(), available.get(0) * 1024, available.get(1), file));
        }
    }

    /** How much of a scanner's error stream is kept: failures quote its first 2,000 characters. */
    static final long STDERR_BYTES = 1024 * 1024;

    /**
     * Reads a scanner's JSON output, or explains why it is unusable.
     *
     * <p><b>Returns empty and never an empty list on failure.</b> The distinction is between
     * "analysed, found nothing" and "not analysed", and it decides the fate of the whole backlog
     * for that finding type: an empty list resolves every existing issue, an absent result
     * changes nothing (decision 0007).
     */
    public static Optional<JsonNode> parseJson(ContainerResult result, String label, List<Integer> acceptedExitCodes) {
        if (!acceptedExitCodes.contains(result.exitCode())) {
            throw ScannerFailureException.exited(label, result.exitCode(), result.stderr());
        }
        String payload = result.stdout().strip();
        if (payload.isEmpty()) {
            return Optional.empty();
        }
        try {
            return Optional.of(MAPPER.readTree(payload));
        } catch (IOException notJson) {
            return Optional.empty();
        }
    }

    /**
     * Collects the two streams apart.
     *
     * <p>The Docker protocol multiplexes them over one connection and tags each frame; keeping
     * the tag is what stops the scanner's warnings from being interleaved into the JSON.
     */
    static final class StreamCollector extends ResultCallback.Adapter<Frame> {

        private final java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        private final java.io.ByteArrayOutputStream err = new java.io.ByteArrayOutputStream();
        private final long stdoutLimit;
        private final long stderrLimit;
        private volatile boolean overflowed;

        /**
         * @param stdoutLimit past this, the collection stops and {@link #overflowed()} says so
         * @param stderrLimit past this, the rest of the error stream is dropped: only its beginning
         *     is ever shown, and a scanner failing noisily is not a scanner failing twice
         */
        StreamCollector(long stdoutLimit, long stderrLimit) {
            this.stdoutLimit = stdoutLimit;
            this.stderrLimit = stderrLimit;
        }

        @Override
        public void onNext(Frame frame) {
            byte[] payload = frame.getPayload();
            if (frame.getStreamType() == StreamType.STDERR) {
                int room = (int) Math.max(0, Math.min(payload.length, stderrLimit - err.size()));
                err.write(payload, 0, room);
                return;
            }
            if (overflowed) {
                return;
            }
            if (out.size() + (long) payload.length > stdoutLimit) {
                overflowed = true;
                try {
                    // Stops the daemon's stream: reading the rest only to discard it is the cost this avoids.
                    close();
                } catch (IOException alreadyClosing) {
                    // The stream is going away either way.
                }
                return;
            }
            out.write(payload, 0, payload.length);
        }

        boolean overflowed() {
            return overflowed;
        }

        String stdout() {
            return out.toString();
        }

        String stderr() {
            return err.toString();
        }

    }
}
