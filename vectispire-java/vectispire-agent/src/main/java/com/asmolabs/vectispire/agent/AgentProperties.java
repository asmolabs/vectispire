package com.asmolabs.vectispire.agent;

import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.ConstructorBinding;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Everything the agent needs to know, and nothing more.
 *
 * <p>The three durations are bounded — {@code claimWait} and {@code retryDelay} between a second and
 * five minutes, {@code heartbeat} between five seconds and ten minutes. A value under its floor stops
 * the start with a message naming the property; a value over its ceiling is lowered to it, and the
 * start says so in a warning that names the property.
 *
 * @param url the control plane's address. A fixed configuration value, which is why redirects
 *     are refused: it has no reason to redirect, and following one would send a scan's results
 *     — or the claim that carries the API key — to a host nobody declared
 * @param token the API key shown once when the agent was created
 * @param claimWait how long the server is asked to hold a claim open. The long wait is the server's
 *     to bear, so a queued scan leaves within the second rather than at the next poll
 * @param heartbeat the interval between two signs of life during a scan. <b>Periodic, not tied
 *     to the scanner's steps</b>: a beat sent per step would go silent for the fifteen minutes
 *     Semgrep can take on a large repository, and the lease would lapse while it progresses
 * @param signingKey the base64 Ed25519 seed whose public half an administrator pinned on this
 *     agent's row, or blank for an agent whose results are not attested. <b>Configuration and not
 *     an announcement</b>: a key this agent could publish over the protocol would prove nothing
 *     its API key does not already prove — see {@code ResultAttestation}. Provide it the way the
 *     API key is provided, as a secret of this process
 * @param images the scanner images, blank meaning "the pinned digest". <b>The agent needs these
 *     more than the control plane does</b>: it is the component deployed on somebody else's
 *     network, which is exactly where pulls go through an internal registry rather than to Docker
 *     Hub. An agent that cannot name its registry cannot run at all there. {@code pluginRegistry}
 *     is the one plugin images are relocated to — the host swapped, the path and digest kept — so
 *     the mirror serves a plugin and cannot substitute another (decision 0017). {@code
 *     pluginSignatureRequired}, on by default, refuses a plugin whose manifest declares no signer
 *     unless the governor waived the requirement for it; off, this agent runs unsigned plugins — its
 *     operator's explicit choice, for its own host
 * @param vulnerabilityDbDir where the matcher's database is downloaded once and shared, read-only, by
 *     every scan this agent runs; blank is a directory beside the workspaces
 * @param executor what runs the scanners: {@code docker}, a daemon this agent reaches, or {@code
 *     kubernetes}, a pod per run in a namespace of its own (decision 0045) — see {@link Executor}
 */
@ConfigurationProperties("vectispire.agent")
public record AgentProperties(
        String url,
        String token,
        @DefaultValue("30s") Duration claimWait,
        @DefaultValue("10s") Duration retryDelay,
        @DefaultValue("60s") Duration heartbeat,
        @DefaultValue("docker") String scannerEngine,
        @DefaultValue("") String signingKey,
        @DefaultValue Images images,
        @DefaultValue("") String vulnerabilityDbDir,
        @DefaultValue Executor executor) {

    private static final Logger log = LoggerFactory.getLogger(AgentProperties.class);

    /** Blank keeps the digest the agent ships with — see {@code ScannerImages.withOverrides}. */
    public record Images(
            @DefaultValue("") String syft,
            @DefaultValue("") String grype,
            @DefaultValue("") String gitleaks,
            @DefaultValue("") String checkov,
            @DefaultValue("") String semgrep,
            @DefaultValue("") String pluginRegistry,
            @DefaultValue("true") boolean pluginSignatureRequired) {}

    /**
     * @param kind {@code docker} or {@code kubernetes}; anything else stops the start
     * @param kubernetes read only when {@code kind} is {@code kubernetes}
     */
    public record Executor(@DefaultValue("docker") String kind, @DefaultValue Kubernetes kubernetes) {

        public Executor {
            kind = kind == null || kind.isBlank() ? "docker" : kind.trim().toLowerCase(java.util.Locale.ROOT);
            kubernetes = kubernetes == null ? new Kubernetes("", "vectispire-agent", "", "", Duration.ofMinutes(5), "") : kubernetes;
        }
    }

    /**
     * @param namespace the scans' namespace, required: the one the chart labels {@code restricted} and
     *     binds this agent's Role in
     * @param name this agent's name on every scan pod, so its start can sweep what a crash left — the
     *     release's name, stable across restarts, never the pod's
     * @param helperImage the static busybox the wrapper runs; blank keeps the pinned one
     * @param user {@code uid:gid} for a run that names none; blank is this process's own
     * @param startTimeout how long a pod may take to be scheduled, pull and receive its workspace
     * @param placement the scan pods' {@code nodeSelector}, {@code tolerations} and {@code affinity}, as
     *     JSON — the agents' own pool, which the chart passes through
     * @param requireIsolation refuse the start unless scan pods are proved cut off from the API server — on,
     *     except where the chart renders no policy at the operator's explicit acknowledgement
     * @param probeTarget the {@code address:port} the probe tries; blank is the API server as this pod sees
     *     it ({@code KUBERNETES_SERVICE_HOST} and {@code KUBERNETES_SERVICE_PORT})
     * @param cpuMillis what each scan pod's scanner is given and limited to, in thousandths of a CPU. <b>Set,
     *     never derived from this JVM's cores</b>: those are the agent pod's view of its node, and scan pods
     *     asking for all but one of them could not be scheduled beside anything — measured, on k3s
     * @param memoryMiB the scanner's memory, request and limit alike
     */
    public record Kubernetes(
            @DefaultValue("") String namespace,
            @DefaultValue("vectispire-agent") String name,
            @DefaultValue("") String helperImage,
            @DefaultValue("") String user,
            @DefaultValue("5m") Duration startTimeout,
            @DefaultValue("") String placement,
            @DefaultValue("true") boolean requireIsolation,
            @DefaultValue("") String probeTarget,
            @DefaultValue("2000") int cpuMillis,
            @DefaultValue("2048") int memoryMiB) {

        /** The one the binder uses — marked, because the convenience constructor below makes two (see the outer record's). */
        @ConstructorBinding
        public Kubernetes {
            namespace = namespace == null ? "" : namespace.trim();
            name = name == null || name.isBlank() ? "vectispire-agent" : name.trim();
            helperImage = helperImage == null ? "" : helperImage.trim();
            user = user == null ? "" : user.trim();
            startTimeout = startTimeout == null ? Duration.ofMinutes(5) : startTimeout;
            placement = placement == null ? "" : placement.trim();
            probeTarget = probeTarget == null ? "" : probeTarget.trim();
            if (cpuMillis <= 0 || memoryMiB <= 0) {
                throw new IllegalArgumentException("vectispire.agent.executor.kubernetes.cpu-millis and memory-mib are "
                        + "positive: a scan pod with no limit is not in the closed shape. The agent does not start.");
            }
        }

        /** Without the two probe settings: isolation required, against the API server. */
        public Kubernetes(String namespace, String name, String helperImage, String user, Duration startTimeout,
                String placement) {
            this(namespace, name, helperImage, user, startTimeout, placement, true, "", 2000, 2048);
        }
    }

    /** The pinned scanner digests, for a caller with no opinion about the registry. */
    public AgentProperties(
            String url,
            String token,
            Duration claimWait,
            Duration retryDelay,
            Duration heartbeat,
            String scannerEngine) {
        this(url, token, claimWait, retryDelay, heartbeat, scannerEngine, "",
                new Images("", "", "", "", "", "", false), "", null);
    }

    /**
     * **The one Spring binds, and it has to be told.** A record with a single constructor binds
     * through it without being asked; the convenience constructor above made two, and the binder,
     * finding no default one and no marker, refused to create the bean at all. The agent image
     * stopped at start — "No default constructor found" — and nothing saw it: no test binds these
     * properties, and the CI smoke test starts the control plane image, not this one.
     */
    @ConstructorBinding
    public AgentProperties {
        url = url == null ? "" : url.trim().replaceAll("/+$", "");
        token = token == null ? "" : token.trim();
        signingKey = signingKey == null ? "" : signingKey.trim();
        claimWait = bounded("claim-wait", "VECTISPIRE_AGENT_WAIT", claimWait, Duration.ofSeconds(1), Duration.ofMinutes(5));
        retryDelay = bounded("retry-delay", "VECTISPIRE_AGENT_RETRY", retryDelay, Duration.ofSeconds(1), Duration.ofMinutes(5));
        heartbeat = bounded("heartbeat", "VECTISPIRE_AGENT_HEARTBEAT", heartbeat, Duration.ofSeconds(5), Duration.ofMinutes(10));
        // Absent means "no override", which is the same thing every blank field means.
        images = images == null ? new Images("", "", "", "", "", "", false) : images;
        vulnerabilityDbDir = vulnerabilityDbDir == null ? "" : vulnerabilityDbDir.trim();
        executor = executor == null ? new Executor("docker", null) : executor;
    }

    /**
     * A bound, and what the operator is told when a value crosses it.
     *
     * <p><b>Under the floor, the start is refused</b>, as the control plane refuses its durations under
     * a second ({@code ConfigurationPropertiesValidationTest}). The value there is almost always
     * {@code 30} with its unit forgotten, which binds as thirty milliseconds: raising it to the floor
     * (until 0.11.1, first in silence and then with a warning) did land on a value the agent works at,
     * but not on the one its operator meant — a poll every second where thirty were asked — and a
     * warning in a log nobody reads at start is how that went unseen. A message that stops the start
     * is read.
     *
     * <p><b>Over the ceiling, still lowered and warned, not refused.</b> The ceiling honours what was
     * asked in its direction — the control plane holds a claim thirty seconds whatever is asked, and a
     * ten-minute beat is still under the default twenty-minute lease — and an agent configured with a
     * long beat has run on the ceiling since the bound existed; stopping it at an upgrade for a value
     * it worked with would turn a harmless setting into an outage.
     *
     * <p>A null is the convenience constructor's "unset", not an operator's value, and takes the floor
     * without a word.
     */
    private static Duration bounded(String property, String variable, Duration value, Duration min, Duration max) {
        if (value == null) {
            return min;
        }
        if (value.compareTo(min) < 0) {
            throw new IllegalArgumentException(("vectispire.agent.%s (%s) is %s, under its floor of %s: the agent "
                            + "does not start. A bare number is read as milliseconds; write the unit, as in 30s.")
                    .formatted(property, variable, spoken(value), spoken(min)));
        }
        if (value.compareTo(max) > 0) {
            log.warn("vectispire.agent.{} ({}) is {}, over its ceiling of {}: the agent uses {}.",
                    property, variable, spoken(value), spoken(max), spoken(max));
            return max;
        }
        return value;
    }

    /** {@code 30ms}, {@code 30s}, {@code 5m}: the units an operator writes, not {@code PT0.03S}. */
    static String spoken(Duration value) {
        long millis = value.toMillis();
        if (millis % 1000 != 0) {
            return millis + "ms";
        }
        long seconds = millis / 1000;
        return seconds != 0 && seconds % 60 == 0 ? seconds / 60 + "m" : seconds + "s";
    }
}
