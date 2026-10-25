package com.asmolabs.vectispire.agent.kubernetes;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.scanning.ContainerRun;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import com.asmolabs.vectispire.common.scanning.ScannerLimits;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;

class ScanPodsTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final KubernetesExecutor.Settings SETTINGS = new KubernetesExecutor.Settings("scans", "Agent 1",
            KubernetesExecutor.HELPER_IMAGE, "1000:1000", Duration.ofMinutes(5),
            new ScannerLimits(2048L * 1024 * 1024, 512, Duration.ofMinutes(15), 1_500_000_000L), placement());

    private static com.fasterxml.jackson.databind.node.ObjectNode placement() {
        try {
            return (com.fasterxml.jackson.databind.node.ObjectNode) new ObjectMapper().readTree("""
                    {"nodeSelector": {"pool": "scans"},
                     "tolerations": [{"key": "vectispire.dev/agents", "operator": "Exists", "effect": "NoSchedule"}]}""");
        } catch (java.io.IOException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private static JsonNode pod(ContainerRun request, List<String> names) {
        return ScanPods.pod("vs-x", request, SETTINGS, 1000, 1001, names, Duration.ofMinutes(15));
    }

    private static List<String> strings(JsonNode array) {
        List<String> values = new java.util.ArrayList<>();
        array.forEach(value -> values.add(value.asText()));
        return values;
    }

    private static JsonNode container(JsonNode pod, String name) {
        for (String kind : List.of("initContainers", "containers")) {
            for (JsonNode container : pod.path("spec").path(kind)) {
                if (name.equals(container.path("name").asText())) {
                    return container;
                }
            }
        }
        throw new AssertionError("no container " + name);
    }

    private static final ContainerRun SYFT = ContainerRun.of("anchore/syft@sha256:abc", List.of("dir:/repo/source", "-o", "json"),
            List.of(ContainerRun.Mount.readOnly("/w", "/repo")), "syft (SBOM)").withEntrypoint(List.of("/syft"));

    @Test
    void everyContainerIsInTheClosedShape() {
        JsonNode pod = pod(SYFT, List.of(""));
        for (String name : List.of(ScanPods.RECEIVE, ScanPods.SCANNER, ScanPods.HOLDER)) {
            JsonNode security = container(pod, name).path("securityContext");
            assertThat(security.path("runAsNonRoot").asBoolean()).as(name).isTrue();
            assertThat(security.path("runAsUser").asLong()).as(name).isEqualTo(1000);
            assertThat(security.path("runAsGroup").asLong()).as(name).isEqualTo(1001);
            assertThat(security.path("allowPrivilegeEscalation").asBoolean(true)).as(name).isFalse();
            assertThat(security.path("readOnlyRootFilesystem").asBoolean()).as(name).isTrue();
            assertThat(security.path("privileged").asBoolean(true)).as(name).isFalse();
            assertThat(security.path("capabilities").path("drop").toString()).as(name).isEqualTo("[\"ALL\"]");
            assertThat(security.path("seccompProfile").path("type").asText()).as(name).isEqualTo("RuntimeDefault");
        }
        JsonNode spec = pod.path("spec");
        assertThat(spec.path("automountServiceAccountToken").asBoolean(true)).isFalse();
        assertThat(spec.path("restartPolicy").asText()).isEqualTo("Never");
        assertThat(spec.path("nodeSelector").path("pool").asText()).isEqualTo("scans");
        assertThat(spec.path("tolerations").get(0).path("key").asText()).isEqualTo("vectispire.dev/agents");
        assertThat(spec.path("activeDeadlineSeconds").asLong()).isPositive();
    }

    @Test
    void theScannerRunsItsDeclaredProgramWithItsOutputInAFile() {
        JsonNode scanner = container(pod(SYFT, List.of("")), ScanPods.SCANNER);
        assertThat(strings(scanner.path("command"))).containsExactly(
                ScanPods.BUSYBOX, "sh", "-c", "exec \"$@\" >" + ScanPods.STDOUT + " 2>" + ScanPods.STDERR, "scanner",
                "/syft", "dir:/repo/source", "-o", "json");
        assertThat(scanner.has("args")).isFalse();
    }

    @Test
    void anUndeclaredEntrypointKeepsTheImagesOwn() {
        ContainerRun plugin = ContainerRun.of("plugin@sha256:abc", List.of("--in", "/src"), List.of(), "plugin");
        JsonNode scanner = container(pod(plugin, List.of()), ScanPods.SCANNER);
        assertThat(scanner.has("command")).isFalse();
        assertThat(strings(scanner.path("args"))).containsExactly("--in", "/src");
    }

    @Test
    void anOfflineRunIsLabelledForTheDenyingPolicyAndAnOnlineOneForTheOther() {
        assertThat(pod(SYFT, List.of("")).path("metadata").path("labels").path(ScanPods.LABEL_NETWORK).asText())
                .isEqualTo(ScanPods.OFFLINE);
        assertThat(pod(SYFT.withNetwork(), List.of("")).path("metadata").path("labels").path(ScanPods.LABEL_NETWORK).asText())
                .isEqualTo(ScanPods.ONLINE);
        assertThat(pod(SYFT, List.of("")).path("metadata").path("labels").path(ScanPods.LABEL_AGENT).asText())
                .isEqualTo("agent-1");
    }

    @Test
    void limitsAreRequestsAndTheEnvironmentIsTheDockerOne() {
        JsonNode scanner = container(pod(SYFT, List.of("")), ScanPods.SCANNER);
        assertThat(scanner.path("resources").path("limits")).isEqualTo(scanner.path("resources").path("requests"));
        assertThat(scanner.path("resources").path("limits").path("memory").asText()).isEqualTo(String.valueOf(2048L * 1024 * 1024));
        assertThat(scanner.path("resources").path("limits").path("cpu").asText()).isEqualTo("1500m");
        List<String> environment = new java.util.ArrayList<>();
        scanner.path("env").forEach(variable -> environment.add(variable.path("name").asText() + "=" + variable.path("value").asText()));
        assertThat(environment).isEqualTo(ContainerRunner.SCANNER_ENVIRONMENT);
    }

    @Test
    void mountsAreSubdirectoriesOfTheWorkspaceWithTheirAccess() {
        ContainerRun request = ContainerRun.of("i@sha256:abc", List.of(), List.of(
                ContainerRun.Mount.readOnly("/a", "/repo"),
                ContainerRun.Mount.writable("/b", "/out"),
                ContainerRun.Mount.readOnly("/c/key.pub", "/trust/key.pub")), "x");
        JsonNode mounts = container(pod(request, List.of("", "", "key.pub")), ScanPods.SCANNER).path("volumeMounts");
        assertThat(mounts.get(0).path("subPath").asText()).isEqualTo("m0");
        assertThat(mounts.get(0).path("readOnly").asBoolean()).isTrue();
        assertThat(mounts.get(1).path("subPath").asText()).isEqualTo("m1");
        assertThat(mounts.get(1).path("readOnly").asBoolean()).isFalse();
        assertThat(mounts.get(2).path("subPath").asText()).isEqualTo("m2/key.pub");
        assertThat(mounts.get(2).path("mountPath").asText()).isEqualTo("/trust/key.pub");
    }

    @Test
    void aBoundedOutputIsAMemoryVolumeOfItsSize() {
        ContainerRun request = SYFT.runningAs("1000:1000")
                .withBoundedOutput(new ContainerRun.BoundedOutput("/output", 4096, "busybox", "report.json"));
        JsonNode pod = pod(request, List.of(""));
        JsonNode volume = null;
        for (JsonNode candidate : pod.path("spec").path("volumes")) {
            if ("output".equals(candidate.path("name").asText())) {
                volume = candidate;
            }
        }
        assertThat(volume).isNotNull();
        assertThat(volume.path("emptyDir").path("medium").asText()).isEqualTo("Memory");
        assertThat(volume.path("emptyDir").path("sizeLimit").asText()).isEqualTo("4096");
        assertThat(container(pod, ScanPods.HOLDER).path("volumeMounts").toString()).contains("\"mountPath\":\"/output\",\"readOnly\":true");
    }

    @Test
    void anImageThatCannotBePulledIsAFailureAtOnce() throws Exception {
        JsonNode status = JSON.readTree("""
                {"status": {"phase": "Pending", "containerStatuses": [{"name": "scanner",
                  "state": {"waiting": {"reason": "ImagePullBackOff", "message": "Back-off pulling image"}}}]}}""");
        assertThat(ScanPods.failure(status)).hasValueSatisfying(reason -> assertThat(reason).contains("ImagePullBackOff"));
    }

    @Test
    void anEvictedPodIsAFailure() throws Exception {
        JsonNode status = JSON.readTree("""
                {"status": {"phase": "Failed", "reason": "Evicted", "message": "ephemeral local storage usage exceeds"}}""");
        assertThat(ScanPods.failure(status)).hasValueSatisfying(reason -> assertThat(reason).contains("Evicted"));
    }

    @Test
    void aReceiverThatFailedIsAFailure() throws Exception {
        JsonNode status = JSON.readTree("""
                {"status": {"phase": "Pending", "initContainerStatuses": [{"name": "receive",
                  "state": {"terminated": {"exitCode": 1, "reason": "Error"}}}]}}""");
        assertThat(ScanPods.failure(status)).isPresent();
    }

    @Test
    void aPodStillComingUpIsNoFailure() throws Exception {
        JsonNode status = JSON.readTree("""
                {"status": {"phase": "Pending", "conditions": [{"type": "PodScheduled", "status": "False",
                  "reason": "Unschedulable", "message": "0/3 nodes are available"}],
                  "containerStatuses": [{"name": "scanner", "state": {"waiting": {"reason": "ContainerCreating"}}}]}}""");
        assertThat(ScanPods.failure(status)).isEmpty();
        assertThat(ScanPods.pending(status)).contains("0/3 nodes are available");
    }

    @Test
    void placementSaysWhereAPodGoesAndNothingElse() throws Exception {
        var widening = (com.fasterxml.jackson.databind.node.ObjectNode) JSON.readTree("{\"hostNetwork\": true}");
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> new KubernetesExecutor.Settings("scans", "a",
                        KubernetesExecutor.HELPER_IMAGE, "1000:1000", Duration.ofMinutes(5), ScannerLimits.DEFAULT, widening))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("hostNetwork");
    }

    @Test
    void labelValuesAreKubernetesLabelValues() {
        assertThat(ScanPods.labelValue("syft (SBOM of image registry.example/a:1)")).matches("[a-z0-9]([a-z0-9._-]{0,61}[a-z0-9])?");
        assertThat(ScanPods.labelValue("((()))")).isEqualTo("scan");
        assertThat(ScanPods.labelValue("x".repeat(100))).hasSize(63);
    }
}
