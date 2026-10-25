package com.asmolabs.vectispire.agent;

import com.asmolabs.vectispire.agent.kubernetes.KubernetesApi;
import com.asmolabs.vectispire.agent.kubernetes.KubernetesExecutor;
import com.asmolabs.vectispire.common.scanning.ContainerExecutor;
import com.asmolabs.vectispire.common.scanning.ContainerRun;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import com.asmolabs.vectispire.common.scanning.ScannerLimits;
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

    private ExecutorChoice() {}

    /**
     * @param cluster the API server as this pod sees it — asked for only when the kind is {@code kubernetes},
     *     since outside a pod there is none to ask for
     */
    static ContainerExecutor choose(AgentProperties.Executor executor, ObjectMapper json, Supplier<KubernetesApi> cluster) {
        return switch (executor.kind()) {
            case "docker" -> new ContainerRunner();
            case "kubernetes" -> kubernetes(executor.kubernetes(), json, cluster);
            default -> throw new IllegalArgumentException("vectispire.agent.executor.kind (VECTISPIRE_AGENT_EXECUTOR) is \""
                    + executor.kind() + "\": docker or kubernetes. The agent does not start.");
        };
    }

    /** Every setting checked before the cluster is asked for: a refusal names the property, not a missing pod. */
    static KubernetesExecutor kubernetes(AgentProperties.Kubernetes settings, ObjectMapper json, Supplier<KubernetesApi> cluster) {
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
                ScannerLimits.DEFAULT,
                placement(settings.placement(), json));
        KubernetesExecutor executor = new KubernetesExecutor(cluster.get(), checked);
        // What a crash of this agent left: its pods carry its name, and nobody else removes them.
        executor.sweep();
        return executor;
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
