package com.asmolabs.vectispire.common.scanning;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.async.ResultCallback;
import com.github.dockerjava.api.command.CreateContainerResponse;
import com.github.dockerjava.api.command.WaitContainerResultCallback;
import com.github.dockerjava.api.model.Frame;
import com.github.dockerjava.api.model.HostConfig;
import com.github.dockerjava.api.model.StreamType;
import com.github.dockerjava.core.DefaultDockerClientConfig;
import com.github.dockerjava.core.DockerClientImpl;
import com.github.dockerjava.httpclient5.ApacheDockerHttpClient;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

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

    private final DockerClient docker;
    private final ScannerLimits limits;

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
        DefaultDockerClientConfig.Builder builder = DefaultDockerClientConfig.createDefaultConfigBuilder();
        String explicitHost = resolveDockerHost();
        if (explicitHost != null && !explicitHost.isBlank()) {
            builder.withDockerHost(explicitHost);
        }
        DefaultDockerClientConfig config = builder.build();
        return DockerClientImpl.getInstance(
                config,
                new ApacheDockerHttpClient.Builder().dockerHost(config.getDockerHost()).build());
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

    public ContainerResult run(ContainerRun request) {
        Duration timeout = request.timeout() == null ? limits.timeout() : request.timeout();
        ensureImagePresent(request.image(), request.label());

        HostConfig hostConfig = HostConfig.newHostConfig()
                .withBinds(request.binds().stream().map(com.github.dockerjava.api.model.Bind::parse).toList())
                .withNetworkMode(request.network() ? "bridge" : "none")
                .withMemory(limits.memory())
                .withNanoCPUs(limits.nanoCpus())
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
                .withTmpFs(Map.of(
                        "/tmp", "rw,noexec,nosuid,size=" + SCRATCH_MEGABYTES + "m",
                        SCRATCH_HOME, "rw,noexec,nosuid,size=" + SCRATCH_MEGABYTES + "m"))
                // Removed explicitly below rather than by the daemon: an interrupted scan must
                // not leave dead containers accumulating on the machine that scans.
                .withAutoRemove(false);

        var create = docker.createContainerCmd(request.image())
                .withCmd(request.command())
                // **Labelled, because the machine that scans is not necessarily ours.** An
                // agent runs on a shared host where other containers come and go: with no
                // mark, neither an operator nor an orphan sweep can tell what Vectispire
                // launched from the rest.
                .withLabels(Map.of(SCANNER_LABEL, request.label()))
                // Pointed at the tmpfs mounted above. Set for every scanner rather than for the
                // ones known to need it: the next image added is not going to announce that it
                // caches under `$HOME`, it is going to fail a scan on a read-only filesystem
                // and report having found nothing.
                .withEnv(
                        "HOME=" + SCRATCH_HOME,
                        "TMPDIR=/tmp",
                        "XDG_CACHE_HOME=" + SCRATCH_HOME + "/.cache",
                        // Set for every container although only the matcher reads it: the
                        // alternative is per-run environment plumbing for one variable, and a
                        // scanner that does not know the name ignores it. The matcher is also
                        // the only one that mounts anything at this path — without the mount
                        // the variable names a directory on a read-only filesystem, which is
                        // the loud failure rather than the quiet one.
                        "GRYPE_DB_CACHE_DIR=" + DATABASE_CACHE_MOUNT)
                .withHostConfig(hostConfig);
        if (request.asRoot()) {
            create = create.withUser("0:0");
        }

        CreateContainerResponse container = create.exec();

        try {
            docker.startContainerCmd(container.getId()).exec();
            int exitCode = waitFor(container.getId(), timeout, request.label());

            // **Read after the container has finished, not attached before it starts.** A
            // follow-stream attached to a container that has not started yet completes
            // immediately, on output that does not exist yet — which reads as a scanner that
            // printed nothing, and therefore as "analysed, found nothing". The daemon retains
            // the logs, so collecting them afterwards loses none and races on nothing.
            StreamCollector output = new StreamCollector();
            docker.logContainerCmd(container.getId())
                    .withStdOut(true)
                    .withStdErr(true)
                    .withTailAll()
                    .exec(output)
                    .awaitCompletion();

            return new ContainerResult(output.stdout(), output.stderr(), exitCode);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new ScannerFailureException(request.label(), "Interrupted while reading the scanner's output.");
        } finally {
            // In a `finally`: a forgotten container holds its workspace, hence the whole clone,
            // and the machine eventually runs out of disk.
            try {
                docker.removeContainerCmd(container.getId()).withForce(true).exec();
            } catch (RuntimeException alreadyGone) {
                // Nothing to do about it, and nothing worth masking the real error for.
            }
        }
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

    public record ContainerResult(String stdout, String stderr, int exitCode) {}

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
    private static final class StreamCollector extends ResultCallback.Adapter<Frame> {

        private final OutputStream out = new java.io.ByteArrayOutputStream();
        private final OutputStream err = new java.io.ByteArrayOutputStream();

        @Override
        public void onNext(Frame frame) {
            try {
                (frame.getStreamType() == StreamType.STDERR ? err : out).write(frame.getPayload());
            } catch (IOException impossible) {
                throw new IllegalStateException("in-memory write failed", impossible);
            }
        }

        String stdout() {
            return out.toString();
        }

        String stderr() {
            return err.toString();
        }

    }
}
