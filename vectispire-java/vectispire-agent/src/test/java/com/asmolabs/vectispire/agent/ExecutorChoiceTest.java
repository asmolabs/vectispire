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
}
