package com.asmolabs.vectispire.agent;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * What the executor's choice refuses at start, for fixed settings — {@code vectispire-rust/reference/kubernetes/choice.json},
 * which the Rust agent's configuration is held to: the probe's target as configured or as the pod is told it, the
 * placement's JSON, an unknown kind, a missing namespace, a scan pod's resources, and the probe target's split.
 */
class ExecutorChoiceReferenceSetTest {

    private static final ObjectMapper JSON = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);

    @Test
    void whatTheChoiceRefusesAtStart() throws Exception {
        ObjectNode file = JSON.createObjectNode();

        ArrayNode targets = file.putArray("probeTargets");
        for (String configured : List.of("", "10.43.0.1:443", "[fd00::1]:443", "fd00::1:443", "[fd00::1]", "10.43.0.1",
                "kubernetes.default.svc:443", "10.43.0.1:0", "10.43.0.1:65535", "10.43.0.1:65536", "10.43.0.1:+443",
                "10.43.0.1:0443", "1.2.3.4:123456", "1.2.3.4:٤٤٣", "1000.1.1.1:443", "1.2.3:443",
                "[fd00::g]:443", "[1.2.3.4]:443", "[]:443", ":443", "1.2.3.4:", "١.2.3.4:443", "[::ffff:1.2.3.4]:80")) {
            for (URI cluster : List.of(URI.create("https://10.43.0.1:443"), URI.create("https://[fd00::1]:6443"))) {
                if (!configured.isEmpty() && cluster.getPort() == 6443) {
                    continue; // The cluster's address is asked only when none is configured.
                }
                ObjectNode entry = targets.addObject().put("configured", configured).put("cluster", cluster.toString());
                try {
                    String target = ExecutorChoice.probeTarget(kubernetes("ns", 2000, 2048, configured), () -> cluster);
                    entry.put("target", target);
                    // What `requireIsolation` makes of it before the probe.
                    int colon = target.lastIndexOf(':');
                    entry.put("host", target.substring(0, colon).replaceAll("^\\[|]$", ""));
                    entry.put("port", Integer.parseInt(target.substring(colon + 1)));
                } catch (IllegalArgumentException refused) {
                    entry.put("refused", refused.getMessage());
                }
            }
        }

        ArrayNode placements = file.putArray("placements");
        for (String text : List.of("", "{}", "{\"nodeSelector\": {\"a\": \"b\"}}", "[]", "\"x\"", "{", "null", "1",
                "{\"hostPID\": true}", "{} {}", " {\"tolerations\": []} ")) {
            ObjectNode entry = placements.addObject().put("text", text);
            try {
                entry.set("placement", ExecutorChoice.placement(text.strip(), new ObjectMapper()));
            } catch (IllegalArgumentException refused) {
                entry.put("refused", refused.getMessage());
            }
        }

        ArrayNode kinds = file.putArray("kinds");
        for (String kind : List.of("", "docker", " Docker ", "KUBERNETES", "podman", "kubernetes ")) {
            AgentProperties.Executor executor = new AgentProperties.Executor(kind, null);
            ObjectNode entry = kinds.addObject().put("configured", kind).put("kind", executor.kind());
            if (!List.of("docker", "kubernetes").contains(executor.kind())) {
                try {
                    ExecutorChoice.choose(executor, new ObjectMapper(), () -> null, Path.of("db"));
                } catch (IllegalArgumentException refused) {
                    entry.put("refused", refused.getMessage());
                }
            }
        }

        try {
            ExecutorChoice.kubernetes(kubernetes("", 2000, 2048, ""), new ObjectMapper(), () -> null, Path.of("db"));
        } catch (IllegalArgumentException refused) {
            file.put("noNamespace", refused.getMessage());
        }
        try {
            ExecutorChoice.kubernetes(new AgentProperties.Kubernetes("ns", "a", "", "1000:1000", Duration.ofMinutes(5), "[]"),
                    new ObjectMapper(), () -> null, Path.of("db"));
        } catch (IllegalArgumentException refused) {
            file.put("placementNotAnObject", refused.getMessage());
        }
        ArrayNode resources = file.putArray("resources");
        for (int[] pair : new int[][] {{2000, 2048}, {0, 2048}, {2000, 0}, {-1, -1}, {1, 1}}) {
            ObjectNode entry = resources.addObject().put("cpuMillis", pair[0]).put("memoryMiB", pair[1]);
            try {
                kubernetes("ns", pair[0], pair[1], "");
                entry.putNull("refused");
            } catch (IllegalArgumentException refused) {
                entry.put("refused", refused.getMessage());
            }
        }
        RustReference.expect("kubernetes/choice.json", JSON.writeValueAsString(file) + "\n");
    }

    private static AgentProperties.Kubernetes kubernetes(String namespace, int cpuMillis, int memoryMiB, String probeTarget) {
        return new AgentProperties.Kubernetes(namespace, "vectispire-agent", "", "1000:1000", Duration.ofMinutes(5), "", true,
                probeTarget, cpuMillis, memoryMiB, "", "");
    }
}
