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

    /** The chart's `scans-admission-policy.yaml`, as it renders for a pool selected by `vectispire.dev/agents=true`. */
    private static final String ADMISSION_POLICY = """
            apiVersion: admissionregistration.k8s.io/v1
            kind: ValidatingAdmissionPolicy
            metadata: {name: test-scan-pods}
            spec:
              failurePolicy: Fail
              matchConstraints:
                resourceRules: [{apiGroups: [""], apiVersions: [v1], operations: [CREATE], resources: [pods]}]
              validations:
              - expression: "!has(object.spec.nodeName) || object.spec.nodeName == ''"
                message: "A scan pod is placed by the scheduler: it never names its node."
              - expression: "has(object.spec.automountServiceAccountToken) && object.spec.automountServiceAccountToken == false"
                message: "A scan pod mounts no service account token."
              - expression: "has(object.spec.nodeSelector) && \\"vectispire.dev/agents\\" in object.spec.nodeSelector && object.spec.nodeSelector[\\"vectispire.dev/agents\\"] == \\"true\\""
                message: "A scan pod runs on the agents' pool: nodeSelector vectispire.dev/agents=true."
            ---
            apiVersion: admissionregistration.k8s.io/v1
            kind: ValidatingAdmissionPolicyBinding
            metadata: {name: test-scan-pods}
            spec:
              policyName: test-scan-pods
              validationActions: [Deny]
              matchResources: {namespaceSelector: {matchLabels: {kubernetes.io/metadata.name: %s}}}
            """;

    private static com.fasterxml.jackson.databind.node.ObjectNode bare(String name) throws Exception {
        return (com.fasterxml.jackson.databind.node.ObjectNode) JSON.readTree("""
                {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "%s"},
                 "spec": {"restartPolicy": "Never", "automountServiceAccountToken": false,
                   "containers": [{"name": "c", "image": "%s", "command": ["true"],
                     "securityContext": {"runAsNonRoot": true, "runAsUser": 1000, "allowPrivilegeEscalation": false,
                       "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}}}]}}
                """.formatted(name, K3sCluster.BUSYBOX));
    }

    /** The API server's refusal of {@code pod}, waited for while the policy it is applied from takes effect. */
    private static String refusal(com.fasterxml.jackson.databind.node.ObjectNode pod) throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(60).toNanos();
        while (true) {
            try {
                cluster.api().createPodDryRun(K3sCluster.NAMESPACE, pod);
            } catch (com.asmolabs.vectispire.agent.kubernetes.KubernetesException refused) {
                return refused.getMessage();
            }
            assertThat(System.nanoTime()).as("the policy refused the pod").isLessThan(deadline);
            Thread.sleep(1000);
        }
    }

    @Test
    void theAdmissionPolicyKeepsScanPodsOnTheirPool_andTheAgentStillStartsUnderIt() throws Exception {
        String node = cluster.kubectl("get", "nodes", "-o", "jsonpath={.items[0].metadata.name}").strip();
        cluster.kubectl("label", "node", node, "vectispire.dev/agents=true", "--overwrite");
        cluster.apply(ADMISSION_POLICY.formatted(K3sCluster.NAMESPACE));
        try {
            assertThat(refusal(bare("no-selector"))).contains("agents' pool");

            var named = bare("named");
            ((com.fasterxml.jackson.databind.node.ObjectNode) named.get("spec")).putObject("nodeSelector").put("vectispire.dev/agents", "true");
            ((com.fasterxml.jackson.databind.node.ObjectNode) named.get("spec")).put("nodeName", node);
            assertThat(refusal(named)).contains("never names its node");

            var token = bare("token");
            ((com.fasterxml.jackson.databind.node.ObjectNode) token.get("spec")).putObject("nodeSelector").put("vectispire.dev/agents", "true");
            ((com.fasterxml.jackson.databind.node.ObjectNode) token.get("spec")).remove("automountServiceAccountToken");
            assertThat(refusal(token)).contains("no service account token");

            // The agent's own start: its Pod Security dry run is refused by Pod Security alone, and a scan pod with
            // the pool's placement runs.
            KubernetesExecutor executor = ExecutorChoice.kubernetes(new AgentProperties.Kubernetes(K3sCluster.NAMESPACE,
                    "vs-agent", "", "1000:1000", Duration.ofMinutes(3), "{\"nodeSelector\":{\"vectispire.dev/agents\":\"true\"}}",
                    false, apiService + ":443", 250, 128, "", ""), JSON, cluster::api, java.nio.file.Path.of("db"));
            assertThat(executor.run(com.asmolabs.vectispire.common.scanning.ContainerRun.of(KubernetesExecutor.HELPER_IMAGE,
                    java.util.List.of("sh", "-c", "echo scanned"), java.util.List.of(), "pinned run")
                    .withEntrypoint(java.util.List.of())).stdout()).isEqualTo("scanned\n");
        } finally {
            cluster.kubectl("delete", "validatingadmissionpolicybinding,validatingadmissionpolicy", "test-scan-pods",
                    "--ignore-not-found");
            cluster.kubectl("label", "node", node, "vectispire.dev/agents-");
            // Deleted is not yet unenforced: the API server stops applying a policy a moment later, and the next
            // test's pods carry no pool selector. Waited for, rather than left to the order the tests run in.
            long deadline = System.nanoTime() + Duration.ofSeconds(60).toNanos();
            while (true) {
                try {
                    cluster.api().createPodDryRun(K3sCluster.NAMESPACE, bare("unpinned"));
                    break;
                } catch (com.asmolabs.vectispire.agent.kubernetes.KubernetesException stillEnforced) {
                    assertThat(System.nanoTime()).as("the policy stopped being enforced").isLessThan(deadline);
                    Thread.sleep(1000);
                }
            }
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
    void withTheChartsPoliciesItStarts_andItsScannersRunOnceTheirPodIsCutOff() {
        chartPolicies("169.254.0.0/16, " + apiService + "/32, " + apiEndpoint + "/32");
        KubernetesExecutor executor = ExecutorChoice.kubernetes(settings(true), JSON, cluster::api, java.nio.file.Path.of("db"));
        assertThat(executor.isAvailable()).isTrue();
        // Through the gate, offline and online: each pod is refused the API server before its scanner starts.
        var run = com.asmolabs.vectispire.common.scanning.ContainerRun.of(KubernetesExecutor.HELPER_IMAGE,
                java.util.List.of("sh", "-c", "echo scanned"), java.util.List.of(), "gated run").withEntrypoint(java.util.List.of());
        assertThat(executor.run(run).stdout()).isEqualTo("scanned\n");
        assertThat(executor.run(run.withNetwork()).stdout()).isEqualTo("scanned\n");
    }

    @Test
    void aScanPodThatStillReachesTheApiServerNeverStartsItsScanner() {
        // The executor as a start that passed would build it; the policies gone since, or never covering this pod.
        KubernetesExecutor executor = new KubernetesExecutor(cluster.api(), new KubernetesExecutor.Settings(
                K3sCluster.NAMESPACE, "vs-agent", KubernetesExecutor.HELPER_IMAGE, "1000:1000", Duration.ofMinutes(3),
                new com.asmolabs.vectispire.common.scanning.ScannerLimits(128L * 1024 * 1024,
                        com.asmolabs.vectispire.common.scanning.ScannerLimits.DEFAULT.pids(),
                        com.asmolabs.vectispire.common.scanning.ScannerLimits.DEFAULT.timeout(), 250_000_000L,
                        com.asmolabs.vectispire.common.scanning.ScannerLimits.DEFAULT.outputBytes()),
                null, null, apiService + ":443"));
        assertThatThrownBy(() -> executor.run(com.asmolabs.vectispire.common.scanning.ContainerRun.of(
                KubernetesExecutor.HELPER_IMAGE, java.util.List.of("sh", "-c", "echo scanned"), java.util.List.of(), "ungated run")
                .withEntrypoint(java.util.List.of())))
                .isInstanceOf(com.asmolabs.vectispire.common.scanning.ScannerFailureException.class)
                .hasMessageContaining("was not cut off from " + apiService + ":443")
                .hasMessageContaining("the scanner was not started");
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
