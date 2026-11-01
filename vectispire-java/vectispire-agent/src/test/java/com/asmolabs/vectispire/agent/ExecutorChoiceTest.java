package com.asmolabs.vectispire.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.agent.kubernetes.KubernetesApi;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;

class ExecutorChoiceTest {

    private final ObjectMapper json = new ObjectMapper();

    /** Outside a pod there is no cluster: a choice that asks for one when it should not fails here. */
    private static final Supplier<KubernetesApi> NO_CLUSTER = () -> {
        throw new AssertionError("the cluster was asked for");
    };

    private static AgentProperties.Executor kubernetes(String namespace, String placement) {
        return new AgentProperties.Executor("kubernetes",
                new AgentProperties.Kubernetes(namespace, "agent", "", "1000:1000", Duration.ofMinutes(5), placement));
    }

    @Test
    void dockerIsTheDefaultAndNeedsNoCluster() {
        assertThat(ExecutorChoice.choose(new AgentProperties.Executor(null, null), json, NO_CLUSTER, java.nio.file.Path.of("db")))
                .isInstanceOf(ContainerRunner.class);
    }

    @Test
    void anUnknownKindStopsTheStartByName() {
        assertThatThrownBy(() -> ExecutorChoice.choose(new AgentProperties.Executor("podman", null), json, NO_CLUSTER, java.nio.file.Path.of("db")))
                .hasMessageContaining("VECTISPIRE_AGENT_EXECUTOR")
                .hasMessageContaining("podman");
    }

    @Test
    void kubernetesWithoutItsNamespaceStopsTheStart_beforeAskingForTheCluster() {
        assertThatThrownBy(() -> ExecutorChoice.choose(kubernetes("", ""), json, NO_CLUSTER, java.nio.file.Path.of("db")))
                .hasMessageContaining("VECTISPIRE_SCANS_NAMESPACE");
    }

    @Test
    void aScanPodWithoutLimitsStopsTheStart() {
        assertThatThrownBy(() -> new AgentProperties.Kubernetes("scans", "agent", "", "1000:1000", Duration.ofMinutes(5), "",
                true, "", 0, 2048, "", "")).hasMessageContaining("cpu-millis");
    }

    @Test
    void anUnreadablePlacementStopsTheStart_beforeAskingForTheCluster() {
        assertThatThrownBy(() -> ExecutorChoice.choose(kubernetes("scans", "[1]"), json, NO_CLUSTER, java.nio.file.Path.of("db")))
                .hasMessageContaining("VECTISPIRE_KUBERNETES_PLACEMENT");
        assertThatThrownBy(() -> ExecutorChoice.choose(kubernetes("scans", "{\"hostNetwork\": true}"), json, NO_CLUSTER, java.nio.file.Path.of("db")))
                .hasMessageContaining("hostNetwork");
    }

    private static AgentProperties.Kubernetes probing(String target) {
        return new AgentProperties.Kubernetes("scans", "agent", "", "1000:1000", Duration.ofMinutes(5), "",
                true, target, 2000, 2048, "", "");
    }

    @Test
    void theApiServersAddressIsCheckedBeforeTheProbeUsesIt() {
        // The environment's address goes through the cluster check: a refusal there stops the start, and the
        // probe never runs against an address that is not the API server's.
        java.util.Map<String, String> overridden = java.util.Map.of(
                "KUBERNETES_SERVICE_HOST", "10.0.0.99", "KUBERNETES_SERVICE_PORT", "443");
        java.util.function.Supplier<java.net.URI> checked = () -> com.asmolabs.vectispire.agent.kubernetes.ClusterApiAddress.of(
                overridden::get, host -> new java.net.InetAddress[] {java.net.InetAddress.getByName(
                        host.equals(com.asmolabs.vectispire.agent.kubernetes.ClusterApiAddress.SERVICE_NAME) ? "10.43.0.1" : host)});
        assertThatThrownBy(() -> ExecutorChoice.probeTarget(probing(""), checked))
                .hasMessageContaining("KUBERNETES_SERVICE_HOST");

        java.util.Map<String, String> badPort = java.util.Map.of(
                "KUBERNETES_SERVICE_HOST", "10.43.0.1", "KUBERNETES_SERVICE_PORT", "443; rm");
        assertThatThrownBy(() -> ExecutorChoice.probeTarget(probing(""), () -> com.asmolabs.vectispire.agent.kubernetes.ClusterApiAddress.of(
                        badPort::get, host -> new java.net.InetAddress[] {java.net.InetAddress.getByName("10.43.0.1")})))
                .hasMessageContaining("KUBERNETES_SERVICE_PORT");

        assertThat(ExecutorChoice.probeTarget(probing(""), () -> java.net.URI.create("https://10.43.0.1:443")))
                .isEqualTo("10.43.0.1:443");
        assertThat(ExecutorChoice.probeTarget(probing(""), () -> java.net.URI.create("https://[fd00::1]:6443")))
                .isEqualTo("[fd00::1]:6443");
    }

    @Test
    void aConfiguredProbeTargetIsAnAddressAndAPort() {
        java.util.function.Supplier<java.net.URI> never = () -> {
            throw new AssertionError("the environment was read although a target is configured");
        };
        assertThat(ExecutorChoice.probeTarget(probing("10.43.0.1:443"), never)).isEqualTo("10.43.0.1:443");
        assertThat(ExecutorChoice.probeTarget(probing("[fd00::1]:443"), never)).isEqualTo("[fd00::1]:443");
        for (String refused : new String[] {"10.43.0.1", "api.example:443", "10.43.0.1:0", "10.43.0.1:70000",
                "10.43.0.1:https", "fd00::1:443", "[fd00::1]", ":443", "10.43.0.1:443/x"}) {
            assertThatThrownBy(() -> ExecutorChoice.probeTarget(probing(refused), never))
                    .as(refused)
                    .hasMessageContaining("probe-target");
        }
    }
}
