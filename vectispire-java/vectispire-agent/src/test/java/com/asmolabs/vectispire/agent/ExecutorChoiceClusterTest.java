package com.asmolabs.vectispire.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.agent.kubernetes.K3sCluster;
import com.asmolabs.vectispire.agent.kubernetes.KubernetesExecutor;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * The choice as the agent makes it at start, against a real cluster: it sweeps this agent's leftovers, and
 * it starts only where a probe pod — offline, then online — cannot reach the API server (decision 0045 §5).
 * k3s enforces NetworkPolicy, so the same cluster answers both ways depending on the policies applied.
 */
@Tag("kubernetes")
class ExecutorChoiceClusterTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static K3sCluster cluster;
    /** The API server as a pod reaches it: the `kubernetes` Service's address. */
    private static String apiService;
    /** Where that address is translated to, which a policy evaluated after translation sees. */
    private static String apiEndpoint;

    @BeforeAll
    static void start() {
        cluster = new K3sCluster();
        apiService = cluster.kubectl("get", "service", "kubernetes", "-n", "default", "-o", "jsonpath={.spec.clusterIP}").strip();
        apiEndpoint = cluster.kubectl("get", "endpoints", "kubernetes", "-n", "default", "-o",
                "jsonpath={.subsets[0].addresses[0].ip}").strip();
    }

    @AfterAll
    static void stop() {
        if (cluster != null) {
            cluster.close();
        }
    }

    @AfterEach
    void withoutPolicies() {
        cluster.kubectl("delete", "networkpolicy", "--all", "-n", K3sCluster.NAMESPACE);
    }

    private static AgentProperties.Kubernetes settings(boolean requireIsolation) {
        return new AgentProperties.Kubernetes(K3sCluster.NAMESPACE, "vs-agent", "", "1000:1000", Duration.ofMinutes(3), "",
                requireIsolation, apiService + ":443", 250, 128, "", "");
    }

    /** The chart's two policies for the scans' namespace, as `scans-networkpolicy.yaml` renders them. */
    private static void chartPolicies(String onlineExcept) {
        cluster.apply("""
                apiVersion: networking.k8s.io/v1
                kind: NetworkPolicy
                metadata: {name: scans-offline, namespace: %1$s}
                spec:
                  podSelector: {}
                  policyTypes: [Ingress, Egress]
                ---
                apiVersion: networking.k8s.io/v1
                kind: NetworkPolicy
                metadata: {name: scans-online, namespace: %1$s}
                spec:
                  podSelector: {matchLabels: {vectispire.dev/network: egress}}
                  policyTypes: [Egress]
                  egress:
                  - ports: [{port: 53, protocol: UDP}, {port: 53, protocol: TCP}]
                  - to: [{ipBlock: {cidr: 0.0.0.0/0, except: [%2$s]}}]
                """.formatted(K3sCluster.NAMESPACE, onlineExcept));
    }

    @Test
    void aScansNamespaceThatWouldAdmitAPrivilegedPodStopsTheStart() {
        // A namespace created outside the chart, without the label: the Role's ceiling is gone (review, M1).
        cluster.kubectl("label", "namespace", K3sCluster.NAMESPACE, "pod-security.kubernetes.io/enforce-");
        try {
            assertThatThrownBy(() -> ExecutorChoice.kubernetes(settings(false), JSON, cluster::api, java.nio.file.Path.of("db")))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("would admit a privileged pod");
        } finally {
            cluster.kubectl("label", "namespace", K3sCluster.NAMESPACE, "pod-security.kubernetes.io/enforce=restricted",
                    "--overwrite");
        }
    }

    @Test
    void withoutPoliciesTheStartIsRefused() {
        assertThatThrownBy(() -> ExecutorChoice.kubernetes(settings(true), JSON, cluster::api, java.nio.file.Path.of("db")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("offline scan pod reached the API server")
                .hasMessageContaining("does not start");
    }

    @Test
    void withTheChartsPoliciesItStarts() {
        chartPolicies("169.254.0.0/16, " + apiService + "/32, " + apiEndpoint + "/32");
        assertThat(ExecutorChoice.kubernetes(settings(true), JSON, cluster::api, java.nio.file.Path.of("db")).isAvailable()).isTrue();
    }

    @Test
    void anOnlinePolicyThatLetsScanPodsReachTheApiServerIsRefused() {
        // The gap the chart's check found: an online rule whose exclusions miss the API server.
        chartPolicies("169.254.0.0/16");
        assertThatThrownBy(() -> ExecutorChoice.kubernetes(settings(true), JSON, cluster::api, java.nio.file.Path.of("db")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("online scan pod reached the API server");
    }

    @Test
    void choosingKubernetesSweepsThisAgentsLeftoversAndNoOneElses() throws Exception {
        for (String[] pod : new String[][] {{"left-by-crash", "vs-agent"}, {"another-agents", "someone-else"}}) {
            cluster.api().createPod(K3sCluster.NAMESPACE, JSON.readTree("""
                    {"apiVersion": "v1", "kind": "Pod",
                     "metadata": {"name": "%s", "labels": {"vectispire.dev/agent": "%s"}},
                     "spec": {"restartPolicy": "Never", "automountServiceAccountToken": false,
                       "containers": [{"name": "c", "image": "%s", "command": ["sleep", "600"],
                         "securityContext": {"runAsNonRoot": true, "runAsUser": 1000, "allowPrivilegeEscalation": false,
                           "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}}}]}}
                    """.formatted(pod[0], pod[1], K3sCluster.BUSYBOX)));
        }
        // Isolation not required: the operator's acknowledged choice, and the sweep alone is under test here.
        KubernetesExecutor executor = ExecutorChoice.kubernetes(settings(false), JSON, cluster::api, java.nio.file.Path.of("db"));

        assertThat(executor.isAvailable()).isTrue();
        long deadline = System.nanoTime() + Duration.ofMinutes(1).toNanos();
        while (!cluster.api().pods(K3sCluster.NAMESPACE, "vectispire.dev/agent=vs-agent").isEmpty()) {
            assertThat(System.nanoTime()).as("this agent's leftovers swept").isLessThan(deadline);
            Thread.sleep(250);
        }
        assertThat(cluster.api().pods(K3sCluster.NAMESPACE, "vectispire.dev/agent=someone-else")).hasSize(1);
    }
}
