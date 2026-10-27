package com.asmolabs.vectispire.agent;

import com.asmolabs.vectispire.agent.kubernetes.KubernetesApi;
import com.asmolabs.vectispire.agent.kubernetes.KubernetesExecutor;
import com.asmolabs.vectispire.common.scanning.ContainerExecutor;
import com.asmolabs.vectispire.common.scanning.ContainerRun;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import com.asmolabs.vectispire.common.scanning.ScannerLimits;
import com.asmolabs.vectispire.common.scanning.scanners.VulnerabilityDatabase;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Supplier;

/**
 * What runs the scanners on this agent, chosen once at start (decision 0045): the Docker daemon it reaches,
 * or a pod per run in the scans' namespace.
 *
 * <p><b>Refused at start, never discovered at the first scan.</b> An unknown kind, a Kubernetes executor
 * with no namespace or an unreadable placement stops the agent with the property named — the same rule
 * {@link AgentProperties} applies to its durations. A misconfigured executor that started would claim scans
 * and fail every one of them.
 */
final class ExecutorChoice {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(ExecutorChoice.class);

    private ExecutorChoice() {}

    /**
     * @param cluster the API server as this pod sees it — asked for only when the kind is {@code kubernetes},
     *     since outside a pod there is none to ask for
     */
    static ContainerExecutor choose(AgentProperties.Executor executor, ObjectMapper json, Supplier<KubernetesApi> cluster,
            Path matcherDatabase) {
        return switch (executor.kind()) {
            case "docker" -> new ContainerRunner();
            case "kubernetes" -> kubernetes(executor.kubernetes(), json, cluster, matcherDatabase);
            default -> throw new IllegalArgumentException("vectispire.agent.executor.kind (VECTISPIRE_AGENT_EXECUTOR) is \""
                    + executor.kind() + "\": docker or kubernetes. The agent does not start.");
        };
    }

    /**
     * Every setting checked before the cluster is asked for: a refusal names the property, not a missing pod.
     *
     * @param matcherDatabase the matcher's database directory on this agent, whose generations the cache serves
     */
    static KubernetesExecutor kubernetes(AgentProperties.Kubernetes settings, ObjectMapper json, Supplier<KubernetesApi> cluster,
            Path matcherDatabase) {
        if (settings.namespace().isEmpty()) {
            throw new IllegalArgumentException("vectispire.agent.executor.kubernetes.namespace (VECTISPIRE_SCANS_NAMESPACE) "
                    + "is required with the Kubernetes executor: the namespace whose Role this agent holds. The agent does not start.");
        }
        KubernetesExecutor.Settings checked = new KubernetesExecutor.Settings(
                settings.namespace(),
                settings.name(),
                settings.helperImage().isEmpty() ? KubernetesExecutor.HELPER_IMAGE : settings.helperImage(),
                settings.user().isEmpty() ? ownUser() : settings.user(),
                settings.startTimeout(),
                // The pod's own resources, never the default's CPU count: see AgentProperties.Kubernetes#cpuMillis.
                new ScannerLimits(settings.memoryMiB() * 1024L * 1024, ScannerLimits.DEFAULT.pids(),
                        ScannerLimits.DEFAULT.timeout(), settings.cpuMillis() * 1_000_000L, ScannerLimits.DEFAULT.outputBytes()),
                placement(settings.placement(), json),
                settings.matcherCacheClaim().isEmpty() ? null : new KubernetesExecutor.MatcherCache(
                        settings.matcherCacheClaim(), matcherDatabase.resolve(VulnerabilityDatabase.GENERATIONS),
                        settings.nodeName()));
        KubernetesExecutor executor = new KubernetesExecutor(cluster.get(), checked);
        // What a crash of this agent left: its pods carry its name, and nobody else removes them.
        executor.sweep();
        requirePodSecurity(executor, settings.namespace());
        if (settings.requireIsolation()) {
            requireIsolation(executor, probeTarget(settings));
        } else {
            log.warn("vectispire.agent.executor.kubernetes.require-isolation is false: whether scan pods are cut off "
                    + "from the network is not checked. Scanners read hostile trees.");
        }
        return executor;
    }

    /**
     * **Refuses the start unless scan pods are cut off**, offline and online alike, from the API server
     * (decision 0045 §5). A CNI that does not enforce NetworkPolicy accepts the chart's policies and ignores
     * them; an agent that scanned there would run every scanner with the cluster in reach. A probe that could
     * not run is a refusal too: an unknown is not a proof.
     */
    static void requireIsolation(KubernetesExecutor executor, String target) {
        int colon = target.lastIndexOf(':');
        String host = target.substring(0, colon).replaceAll("^\\[|]$", "");
        int port = Integer.parseInt(target.substring(colon + 1));
        for (boolean online : new boolean[] {false, true}) {
            KubernetesExecutor.Isolation found;
            try {
                found = executor.probe(host, port, online);
            } catch (RuntimeException unknown) {
                throw new IllegalStateException("Whether scan pods are cut off from the network could not be checked: "
                        + unknown.getMessage() + " The agent does not start.", unknown);
            }
            if (found != KubernetesExecutor.Isolation.ENFORCED) {
                throw new IllegalStateException("An " + (online ? "online" : "offline") + " scan pod reached the API "
                        + "server at " + target + ": scan pods are not cut off. This cluster's CNI does not enforce "
                        + "NetworkPolicy, or the chart's policies for the scans' namespace are missing. The agent does "
                        + "not start; scanners read hostile trees.");
            }
        }
        log.info("Scan pods are cut off from the API server at {}, offline and online: the policies are enforced.", target);
    }

    /**
     * **Refuses the start unless the scans' namespace refuses a privileged pod** — Pod Security {@code
     * restricted}, the ceiling on what this agent's Role can start (decision 0045 §3). Not something to turn
     * off: a namespace without it lets a compromised agent start a root pod on any node. The chart labels the
     * namespace it creates; one created elsewhere is checked here, since nothing else can (review of
     * 2026-10-26, M1).
     */
    static void requirePodSecurity(KubernetesExecutor executor, String namespace) {
        KubernetesExecutor.Isolation found;
        try {
            found = executor.podSecurity();
        } catch (RuntimeException unknown) {
            throw new IllegalStateException("Whether the scans' namespace " + namespace + " refuses a privileged pod could "
                    + "not be checked: " + unknown.getMessage() + " The agent does not start.", unknown);
        }
        if (found != KubernetesExecutor.Isolation.ENFORCED) {
            throw new IllegalStateException("The scans' namespace " + namespace + " would admit a privileged pod: label it "
                    + "pod-security.kubernetes.io/enforce=restricted. The agent does not start; its Role creates pods there.");
        }
        log.info("The scans' namespace {} refuses a privileged pod: Pod Security restricted is enforced.", namespace);
    }

    private static String probeTarget(AgentProperties.Kubernetes settings) {
        if (!settings.probeTarget().isEmpty()) {
            return settings.probeTarget();
        }
        String host = System.getenv("KUBERNETES_SERVICE_HOST");
        String port = System.getenv("KUBERNETES_SERVICE_PORT");
        if (host == null || port == null) {
            throw new IllegalStateException("The isolation probe has no target: KUBERNETES_SERVICE_HOST is not set and "
                    + "vectispire.agent.executor.kubernetes.probe-target is blank.");
        }
        return (host.contains(":") ? "[" + host + "]" : host) + ":" + port;
    }

    private static ObjectNode placement(String text, ObjectMapper json) {
        if (text.isEmpty()) {
            return json.createObjectNode();
        }
        try {
            JsonNode parsed = json.readTree(text);
            if (parsed instanceof ObjectNode object) {
                return object;
            }
        } catch (IOException unreadable) {
            // Said below, with the property's name.
        }
        throw new IllegalArgumentException("vectispire.agent.executor.kubernetes.placement (VECTISPIRE_KUBERNETES_PLACEMENT) "
                + "is a JSON object of nodeSelector, tolerations and affinity. The agent does not start.");
    }

    /**
     * This process's {@code uid:gid}, read off a file it creates: the owner of every workspace it clones, so
     * the default for a run that names no user.
     */
    private static String ownUser() {
        try {
            Path probe = Files.createTempFile("vectispire-owner", "");
            try {
                return ContainerRun.ownerOf(probe).orElseThrow(() -> new IllegalStateException(
                        "This file system reports no owner: set vectispire.agent.executor.kubernetes.user."));
            } finally {
                Files.deleteIfExists(probe);
            }
        } catch (IOException unwritable) {
            throw new IllegalStateException("The agent's own user could not be read: " + unwritable.getMessage(), unwritable);
        }
    }
}
