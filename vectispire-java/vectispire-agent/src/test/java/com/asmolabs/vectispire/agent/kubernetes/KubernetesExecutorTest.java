package com.asmolabs.vectispire.agent.kubernetes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.scanning.BundledRules;
import com.asmolabs.vectispire.common.scanning.ContainerRun;
import com.asmolabs.vectispire.common.scanning.ContainerRunner.CollectedOutput;
import com.asmolabs.vectispire.common.scanning.ContainerRunner.ContainerResult;
import com.asmolabs.vectispire.common.scanning.ContainerRunner.OutputFile;
import com.asmolabs.vectispire.common.scanning.RulePlacement;
import com.asmolabs.vectispire.common.scanning.ScannerFailureException;
import com.asmolabs.vectispire.common.scanning.ScannerLimits;
import com.asmolabs.vectispire.common.scanning.Workspace;
import com.asmolabs.vectispire.common.scanning.scanners.ScannerImages;
import com.asmolabs.vectispire.common.scanning.scanners.SecretsScanner;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The executor against a real cluster, as the agent's service account: each run a pod under Pod Security
 * {@code restricted}, its mounts copied in and back, its output read from the holder, and every way of not
 * running the scanner a failure — then a real gitleaks, through {@link SecretsScanner}, as a scan runs it.
 */
@Tag("kubernetes")
class KubernetesExecutorTest {

    private static final String SHELL = KubernetesExecutor.HELPER_IMAGE;
    private static K3sCluster cluster;
    private static KubernetesExecutor executor;

    @TempDir
    Path directory;

    @BeforeAll
    static void start() {
        cluster = new K3sCluster();
        executor = executorWith(new ScannerLimits(256L * 1024 * 1024, 512, Duration.ofMinutes(2), 500_000_000L, 1024 * 1024));
    }

    @AfterAll
    static void stop() {
        if (cluster != null) {
            cluster.close();
        }
    }

    private static KubernetesExecutor executorWith(ScannerLimits limits) {
        return new KubernetesExecutor(cluster.api(), new KubernetesExecutor.Settings(K3sCluster.NAMESPACE, "test-agent",
                KubernetesExecutor.HELPER_IMAGE, "1000:1000", Duration.ofMinutes(3), limits, null));
    }

    /** A shell "scanner": the image has no entrypoint, so the declared one is empty and the command is whole. */
    private static ContainerRun shell(String script, ContainerRun.Mount... mounts) {
        return ContainerRun.of(SHELL, List.of("sh", "-c", script), List.of(mounts), "shell test").withEntrypoint(List.of());
    }

    @Test
    void standardOutputIsCapturedWholeAndApartFromTheErrors() {
        ContainerResult result = executor.run(shell("head -c 300000 /dev/zero | tr '\\0' a; echo warned >&2; exit 3"));
        assertThat(result.stdout()).hasSize(300_000).matches("a+");
        assertThat(result.stderr()).isEqualTo("warned\n");
        assertThat(result.exitCode()).isEqualTo(3);
    }

    @Test
    void aReadOnlyMountIsSeenAndCannotBeWritten() throws IOException {
        Path tree = Files.createDirectories(directory.resolve("tree/source"));
        Files.writeString(tree.resolve("main.py"), "print('hello')\n");
        ContainerResult result = executor.run(shell("cat /repo/source/main.py && ! touch /repo/planted 2>/dev/null",
                ContainerRun.Mount.readOnly(directory.resolve("tree").toString(), "/repo")));
        assertThat(result.exitCode()).as(result.stderr()).isZero();
        assertThat(result.stdout()).isEqualTo("print('hello')\n");
    }

    @Test
    void whatTheScannerWritesIntoAWritableMountComesBack_andOnlyThat() throws IOException {
        Path tree = Files.createDirectories(directory.resolve("tree"));
        Files.writeString(tree.resolve("kept.txt"), "kept");
        ContainerResult result = executor.run(shell(
                "echo '[]' > /repo/report.json && mkdir -p /repo/deep && echo x > /repo/deep/x.txt "
                        + "&& ln -s /etc/passwd /repo/link.json",
                ContainerRun.Mount.writable(tree.toString(), "/repo")));
        assertThat(result.exitCode()).as(result.stderr()).isZero();
        assertThat(tree.resolve("report.json")).hasContent("[]");
        assertThat(tree.resolve("deep/x.txt")).hasContent("x");
        assertThat(tree.resolve("kept.txt")).hasContent("kept");
        // A link is not a file it wrote: not brought back, so a report written as one is absent, never followed.
        assertThat(tree.resolve("link.json")).doesNotExist();
    }

    @Test
    void aWrittenNameWithALineBreakIsRefusedNotListed() throws IOException {
        // One name per line: a name with a break in it could make the holder archive a path the scanner chose (L4).
        Path tree = Files.createDirectories(directory.resolve("tree"));
        assertThatThrownBy(() -> executor.run(shell("touch \"/repo/x$(printf '\\ny')\"",
                ContainerRun.Mount.writable(tree.toString(), "/repo"))))
                .isInstanceOf(ScannerFailureException.class)
                .hasMessageContaining("line break");
    }

    @Test
    void anOutputThatCannotBeReadBackIsAFailureNotAnEmptyReport() {
        // The scanner removes the file its output goes to: an absent report, never "" (review, L5).
        assertThatThrownBy(() -> executor.run(shell("rm " + ScanPods.STDOUT + "; echo '[]'")))
                .isInstanceOf(ScannerFailureException.class)
                .hasMessageContaining("could not be read back");
    }

    @Test
    void outputPastTheCeilingIsAFailureNotATruncation() {
        assertThatThrownBy(() -> executor.run(shell("head -c 2000000 /dev/zero")))
                .isInstanceOf(ScannerFailureException.class)
                .hasMessageContaining("more than 1048576 bytes");
    }

    @Test
    void aBoundedOutputIsReadBackAndMeasured() {
        ContainerRun.BoundedOutput bounded = new ContainerRun.BoundedOutput("/output", 64 * 1024, SHELL, "report.json");
        CollectedOutput written = executor.run(shell("echo '{\"ok\":true}' > /output/report.json")
                .runningAs("1000:1000").withBoundedOutput(bounded)).output().orElseThrow();
        assertThat(written.file()).isInstanceOfSatisfying(OutputFile.Read.class,
                read -> assertThat(new String(read.bytes(), StandardCharsets.UTF_8)).isEqualTo("{\"ok\":true}\n"));
        assertThat(written.full()).isFalse();

        CollectedOutput missing = executor.run(shell("true").runningAs("1000:1000").withBoundedOutput(bounded))
                .output().orElseThrow();
        assertThat(missing.file()).isInstanceOf(OutputFile.Missing.class);

        // The kernel's ENOSPC, as on Docker's tmpfs: the directory reports itself full.
        CollectedOutput full = executor.run(shell("head -c 200000 /dev/zero > /output/filler; true")
                .runningAs("1000:1000").withBoundedOutput(bounded)).output().orElseThrow();
        assertThat(full.full()).isTrue();
    }

    @Test
    void aScannerPastItsTimeoutIsStopped() {
        assertThatThrownBy(() -> executor.run(shell("sleep 120").withTimeout(Duration.ofSeconds(5))))
                .isInstanceOf(ScannerFailureException.TimedOut.class);
    }

    @Test
    void aScannerOutOfMemoryIsAFailure() {
        KubernetesExecutor small = executorWith(new ScannerLimits(48L * 1024 * 1024, 512, Duration.ofMinutes(2), 500_000_000L, 1024 * 1024));
        // Either sentence: whether the runtime reports `OOMKilled` or only the kill's 137 is containerd's race
        // (containerd#12260), not ours — the next test holds the second case, which this one cannot choose.
        assertThatThrownBy(() -> returned(small, shell("a=$(head -c 200000000 /dev/zero | tr '\\0' a); echo ${#a}")))
                .isInstanceOf(ScannerFailureException.class)
                .hasMessageContaining("out of memory (its limit is 48 MiB)");
    }

    @Test
    void aScannerKilledWithoutAReasonIsAFailure() {
        // What the runtime reports when its out-of-memory event loses the race to the exit: `Error`, exit 137 —
        // measured on CI's k3s. A child takes the SIGKILL, because the scanner's shell is its container's init and
        // ignores one from inside, and the shell passes its 137 on. `$!`, never `$$`: Kubernetes reads `$$` in a
        // container's command as an escaped `$`.
        assertThatThrownBy(() -> returned(executor, shell("sleep 60 & kill -9 $!; wait $!; exit $?")))
                .isInstanceOf(ScannerFailureException.class)
                .hasMessageContaining("was killed (exit 137, SIGKILL)");
    }

    /** Runs it, and says what came back when it should not have: a bare "expected a throwable" told CI nothing. */
    private static ContainerResult returned(KubernetesExecutor executor, ContainerRun run) {
        ContainerResult result = executor.run(run);
        throw new AssertionError("The run returned, exit " + result.exitCode() + ", standard output \""
                + result.stdout().strip() + "\", errors \"" + result.stderr().strip() + "\".");
    }

    @Test
    void anImageThatCannotBePulledIsAFailure() {
        ContainerRun absent = ContainerRun.of("busybox@sha256:" + "0".repeat(64), List.of("true"), List.of(), "absent image")
                .withEntrypoint(List.of());
        assertThatThrownBy(() -> executor.run(absent))
                .isInstanceOf(ScannerFailureException.class)
                .hasMessageContaining("could not start");
    }

    @Test
    void anUndeclaredEntrypointKeepsTheImagesAndItsOutputIsADiagnostic() {
        ContainerResult result = executor.run(ContainerRun.of(SHELL, List.of("sh", "-c", "echo to-the-log"), List.of(), "plugin test"));
        assertThat(result.exitCode()).isZero();
        assertThat(result.stdout()).isEmpty();
        assertThat(result.stderr()).contains("to-the-log");
    }

    @Test
    void rootIsNeverAsked() {
        assertThatThrownBy(() -> executor.run(shell("true").runningAs("0:0")))
                .isInstanceOf(ScannerFailureException.class)
                .hasMessageContaining("root");
    }

    @Test
    void noPodOutlivesItsRun() throws InterruptedException {
        executor.run(shell("true"));
        long deadline = System.nanoTime() + Duration.ofMinutes(1).toNanos();
        while (!cluster.api().pods(K3sCluster.NAMESPACE, ScanPods.LABEL_AGENT + "=test-agent").isEmpty()) {
            assertThat(System.nanoTime()).as("pods left behind").isLessThan(deadline);
            Thread.sleep(250);
        }
    }

    @Test
    void matcherGenerationsAreSeededOnceAndServedFromTheCacheVolume() throws Exception {
        // The claim in the scans' namespace, as the chart renders it: ReadWriteOnce, k3s's local-path.
        cluster.apply("""
                apiVersion: v1
                kind: PersistentVolumeClaim
                metadata: {name: matcher-cache, namespace: %s}
                spec: {accessModes: [ReadWriteOnce], resources: {requests: {storage: 1Gi}}}
                """.formatted(K3sCluster.NAMESPACE));
        Path generations = Files.createDirectories(directory.resolve("db/generations"));
        KubernetesExecutor cached = new KubernetesExecutor(cluster.api(), new KubernetesExecutor.Settings(
                K3sCluster.NAMESPACE, "test-agent", KubernetesExecutor.HELPER_IMAGE, "1000:1000", Duration.ofMinutes(3),
                new ScannerLimits(256L * 1024 * 1024, 512, Duration.ofMinutes(2), 500_000_000L, 1024 * 1024), null,
                new KubernetesExecutor.MatcherCache("matcher-cache", generations, null)));

        Path first = Files.createDirectories(generations.resolve("1761400000000-aaaaaaaa"));
        Files.writeString(first.resolve("vulnerability.db"), "first");
        assertThat(cached.run(shell("cat /cache/vulnerability.db",
                ContainerRun.Mount.readOnly(first.toString(), "/cache"))).stdout()).isEqualTo("first");

        // A generation never changes once published, so it is not copied again: what the pod reads is the volume's.
        Files.writeString(first.resolve("vulnerability.db"), "changed on the agent");
        ContainerResult again = cached.run(shell("cat /cache/vulnerability.db; touch /cache/x 2>/dev/null && echo WROTE",
                ContainerRun.Mount.readOnly(first.toString(), "/cache")));
        assertThat(again.stdout()).as("served from the volume, read-only").isEqualTo("first");

        // The agent moves to a new generation and retires the old one: the volume follows.
        Path second = Files.createDirectories(generations.resolve("1761500000000-bbbbbbbb"));
        Files.writeString(second.resolve("vulnerability.db"), "second");
        Files.delete(first.resolve("vulnerability.db"));
        Files.delete(first);
        assertThat(cached.run(shell("cat /cache/vulnerability.db",
                ContainerRun.Mount.readOnly(second.toString(), "/cache"))).stdout()).isEqualTo("second");
        assertThat(volumeListing()).contains("1761500000000-bbbbbbbb", "1761500000000-bbbbbbbb.complete")
                .doesNotContain("1761400000000-aaaaaaaa");
    }

    /** The cache volume's generations, listed by a pod of the test's own: what a scan pod cannot see. */
    private static String volumeListing() throws InterruptedException {
        cluster.apply("""
                apiVersion: v1
                kind: Pod
                metadata: {name: cache-lister, namespace: %s}
                spec:
                  restartPolicy: Never
                  automountServiceAccountToken: false
                  volumes: [{name: c, persistentVolumeClaim: {claimName: matcher-cache}}]
                  containers:
                  - name: ls
                    image: %s
                    command: [sh, -c, "ls -a /c/generations; sleep 300"]
                    volumeMounts: [{name: c, mountPath: /c, readOnly: true}]
                    securityContext: {runAsNonRoot: true, runAsUser: 1000, allowPrivilegeEscalation: false,
                      capabilities: {drop: [ALL]}, seccompProfile: {type: RuntimeDefault}}
                """.formatted(K3sCluster.NAMESPACE, K3sCluster.BUSYBOX));
        long deadline = System.nanoTime() + Duration.ofMinutes(2).toNanos();
        while (true) {
            try {
                String listed = cluster.kubectl("logs", "cache-lister", "-n", K3sCluster.NAMESPACE);
                if (!listed.isBlank()) {
                    cluster.kubectl("delete", "pod", "cache-lister", "-n", K3sCluster.NAMESPACE, "--grace-period=0");
                    return listed;
                }
            } catch (IllegalStateException notYet) {
                // Not started yet.
            }
            assertThat(System.nanoTime()).as("the lister ran").isLessThan(deadline);
            Thread.sleep(500);
        }
    }

    @Test
    void gitleaksFindsWhatIsPlanted_asAScanRunsIt() {
        // Generated, so that no file of this repository carries a token gitleaks would flag.
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        StringBuilder token = new StringBuilder("AKIA");
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < 16; i++) {
            token.append(alphabet.charAt(random.nextInt(alphabet.length())));
        }
        var findings = Workspace.withWorkspace(workspace -> {
            try {
                Files.createDirectories(workspace.source());
                Files.writeString(workspace.source().resolve("settings.ini"), "aws_access_key_id = " + token + "\n");
            } catch (IOException failed) {
                throw new IllegalStateException(failed);
            }
            new RulePlacement(BundledRules.materialise()).placeBundled(workspace);
            return new SecretsScanner(executor, ScannerImages.PINNED.gitleaks()).scan(workspace, null);
        }).orElseThrow();
        assertThat(findings).extracting(finding -> finding.file()).containsExactly("settings.ini");
    }
}
