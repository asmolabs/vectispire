package com.asmolabs.vectispire.agent;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.agent.kubernetes.K3sCluster;
import com.asmolabs.vectispire.agent.kubernetes.KubernetesExecutor;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * The choice as the agent makes it at start, against a real cluster: it reaches the namespace and sweeps the
 * pods a crash of this agent left — and only this agent's.
 */
@Tag("kubernetes")
class ExecutorChoiceClusterTest {

    @Test
    void choosingKubernetesSweepsThisAgentsLeftoversAndNoOneElses() throws Exception {
        try (K3sCluster cluster = new K3sCluster()) {
            ObjectMapper json = new ObjectMapper();
            for (String[] pod : new String[][] {{"left-by-crash", "vs-agent"}, {"another-agents", "someone-else"}}) {
                cluster.api().createPod(K3sCluster.NAMESPACE, json.readTree("""
                        {"apiVersion": "v1", "kind": "Pod",
                         "metadata": {"name": "%s", "labels": {"vectispire.dev/agent": "%s"}},
                         "spec": {"restartPolicy": "Never", "automountServiceAccountToken": false,
                           "containers": [{"name": "c", "image": "%s", "command": ["sleep", "600"],
                             "securityContext": {"runAsNonRoot": true, "runAsUser": 1000, "allowPrivilegeEscalation": false,
                               "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}}}]}}
                        """.formatted(pod[0], pod[1], K3sCluster.BUSYBOX)));
            }

            KubernetesExecutor executor = ExecutorChoice.kubernetes(new AgentProperties.Kubernetes(
                    K3sCluster.NAMESPACE, "vs-agent", "", "1000:1000", Duration.ofMinutes(3), ""), json, cluster::api);

            assertThat(executor.isAvailable()).isTrue();
            long deadline = System.nanoTime() + Duration.ofMinutes(1).toNanos();
            while (!cluster.api().pods(K3sCluster.NAMESPACE, "vectispire.dev/agent=vs-agent").isEmpty()) {
                assertThat(System.nanoTime()).as("this agent's leftovers swept").isLessThan(deadline);
                Thread.sleep(250);
            }
            assertThat(cluster.api().pods(K3sCluster.NAMESPACE, "vectispire.dev/agent=someone-else")).hasSize(1);
        }
    }
}
