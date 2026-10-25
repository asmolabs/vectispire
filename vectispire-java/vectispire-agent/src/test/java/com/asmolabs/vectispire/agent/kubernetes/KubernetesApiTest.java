package com.asmolabs.vectispire.agent.kubernetes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/**
 * The client against a real API server, as the agent's service account: the REST calls, and {@code exec}
 * with its standard input closed, its ceiling and its exit codes — the protocol a mock would only echo.
 */
@Tag("kubernetes")
class KubernetesApiTest {

    private static final Duration TIMEOUT = Duration.ofMinutes(2);
    private static K3sCluster cluster;
    private static KubernetesApi api;
    private static final ObjectMapper JSON = new ObjectMapper();

    @BeforeAll
    static void start() throws Exception {
        cluster = new K3sCluster();
        api = cluster.api();
        api.createPod(K3sCluster.NAMESPACE, JSON.readTree("""
                {"apiVersion": "v1", "kind": "Pod",
                 "metadata": {"name": "target", "labels": {"vectispire.dev/run": "client-test"}},
                 "spec": {"restartPolicy": "Never", "automountServiceAccountToken": false,
                   "volumes": [{"name": "work", "emptyDir": {}}],
                   "containers": [{"name": "box", "image": "%s", "command": ["sh", "-c", "sleep 600"],
                     "volumeMounts": [{"name": "work", "mountPath": "/work"}],
                     "securityContext": {"runAsNonRoot": true, "runAsUser": 1000, "runAsGroup": 1000,
                       "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true,
                       "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}}}]}}
                """.formatted(K3sCluster.BUSYBOX)));
        long deadline = System.nanoTime() + TIMEOUT.toNanos();
        while (!"Running".equals(api.pod(K3sCluster.NAMESPACE, "target").orElseThrow().path("status").path("phase").asText())) {
            if (System.nanoTime() > deadline) {
                throw new IllegalStateException("The target pod never ran.");
            }
            Thread.sleep(500);
        }
    }

    @AfterAll
    static void stop() {
        if (cluster != null) {
            cluster.close();
        }
    }

    private static KubernetesApi.ExecResult exec(List<String> command, byte[] stdin, long ceiling) {
        return api.exec(K3sCluster.NAMESPACE, "target", "box", command,
                stdin == null ? null : new ByteArrayInputStream(stdin), ceiling, TIMEOUT);
    }

    @Test
    void aTreeGoesInOverStandardInputAndComesBackOverStandardOutput() throws IOException {
        // Larger than one chunk and one WebSocket frame, so both directions are fragmented.
        byte[] content = new byte[300 * 1024];
        for (int i = 0; i < content.length; i++) {
            content[i] = (byte) ('a' + i % 26);
        }
        KubernetesApi.ExecResult extract = exec(List.of("tar", "-x", "-C", "/work"), tarOf("tree/file.txt", content), 1024);
        assertThat(extract.exitCode()).as(extract.stderr()).isZero();

        KubernetesApi.ExecResult read = exec(List.of("cat", "/work/tree/file.txt"), null, content.length);
        assertThat(read.overCeiling()).isFalse();
        assertThat(read.exitCode()).isZero();
        assertThat(read.stdout()).isEqualTo(content);
    }

    @Test
    void anExitCodeIsTheCommandsOwn() {
        KubernetesApi.ExecResult result = exec(List.of("sh", "-c", "echo oops >&2; exit 3"), null, 16);
        assertThat(result.exitCode()).isEqualTo(3);
        assertThat(result.stderr()).isEqualTo("oops\n");
    }

    @Test
    void passingTheCeilingIsSaidRatherThanCut() {
        KubernetesApi.ExecResult result = exec(List.of("sh", "-c", "head -c 100000 /dev/zero"), null, 1000);
        assertThat(result.overCeiling()).isTrue();
        assertThat(result.stdout().length).isLessThanOrEqualTo(1001);
    }

    @Test
    void aCommandThatCannotStartIsAFailureNotAnExitCode() {
        assertThatThrownBy(() -> exec(List.of("no-such-binary"), null, 16)).isInstanceOf(KubernetesException.class);
    }

    @Test
    void aMissingPodIsRefusedAtTheHandshake() {
        assertThatThrownBy(() -> api.exec(K3sCluster.NAMESPACE, "absent", "box", List.of("true"), null, 16, TIMEOUT))
                .isInstanceOf(KubernetesException.class)
                .extracting(e -> ((KubernetesException) e).status()).isEqualTo(404);
    }

    @Test
    void podsAreListedByLabelAndAnAbsentOneIsEmpty() {
        assertThat(api.pods(K3sCluster.NAMESPACE, "vectispire.dev/run=client-test"))
                .extracting(pod -> pod.path("metadata").path("name").asText()).containsExactly("target");
        assertThat(api.pods(K3sCluster.NAMESPACE, "vectispire.dev/run=nothing")).isEmpty();
        assertThat(api.pod(K3sCluster.NAMESPACE, "absent")).isEmpty();
        api.deletePod(K3sCluster.NAMESPACE, "absent"); // not an error: the outcome wanted already holds
    }

    @Test
    void aPodIsDeletedAndSoAreTheOnesALabelNames() throws Exception {
        for (String name : List.of("left-1", "left-2")) {
            api.createPod(K3sCluster.NAMESPACE, sleeper(name, "crash-leftover"));
        }
        api.deletePods(K3sCluster.NAMESPACE, "vectispire.dev/run=crash-leftover");
        awaitGone("vectispire.dev/run=crash-leftover");

        api.createPod(K3sCluster.NAMESPACE, sleeper("single", "single"));
        api.deletePod(K3sCluster.NAMESPACE, "single");
        awaitGone("vectispire.dev/run=single");
    }

    @Test
    void theRoleReachesNoOtherNamespace() {
        assertThatThrownBy(() -> api.pods("default", "a=b"))
                .isInstanceOf(KubernetesException.class)
                .extracting(e -> ((KubernetesException) e).status()).isEqualTo(403);
    }

    @Test
    void theNamespaceRefusesAPrivilegedPodWhateverTheAgentAsks() throws IOException {
        JsonNode root = JSON.readTree("""
                {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "root"},
                 "spec": {"containers": [{"name": "c", "image": "%s", "securityContext": {"privileged": true}}]}}
                """.formatted(K3sCluster.BUSYBOX));
        assertThatThrownBy(() -> api.createPod(K3sCluster.NAMESPACE, root))
                .isInstanceOf(KubernetesException.class)
                .hasMessageContaining("restricted");
    }

    private static JsonNode sleeper(String name, String run) throws IOException {
        return JSON.readTree("""
                {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "%s", "labels": {"vectispire.dev/run": "%s"}},
                 "spec": {"restartPolicy": "Never", "automountServiceAccountToken": false,
                   "containers": [{"name": "c", "image": "%s", "command": ["sleep", "600"],
                     "securityContext": {"runAsNonRoot": true, "runAsUser": 1000, "allowPrivilegeEscalation": false,
                       "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}}}]}}
                """.formatted(name, run, K3sCluster.BUSYBOX));
    }

    private static void awaitGone(String selector) throws InterruptedException {
        long deadline = System.nanoTime() + TIMEOUT.toNanos();
        while (!api.pods(K3sCluster.NAMESPACE, selector).isEmpty()) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("Pods " + selector + " were never deleted.");
            }
            Thread.sleep(250);
        }
    }

    private static byte[] tarOf(String name, byte[] content) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (TarArchiveOutputStream tar = new TarArchiveOutputStream(bytes)) {
            TarArchiveEntry entry = new TarArchiveEntry(name);
            entry.setSize(content.length);
            tar.putArchiveEntry(entry);
            tar.write(content);
            tar.closeArchiveEntry();
        }
        return bytes.toByteArray();
    }
}
