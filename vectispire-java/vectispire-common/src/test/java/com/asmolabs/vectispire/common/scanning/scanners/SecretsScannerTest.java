package com.asmolabs.vectispire.common.scanning.scanners;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.scanning.ContainerRun;
import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import com.asmolabs.vectispire.common.scanning.ContainerRunner.ContainerResult;
import com.asmolabs.vectispire.common.scanning.ScannerFailureException;
import com.asmolabs.vectispire.common.scanning.Workspace;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The secrets scanner's reading of the file its container leaves, without a daemon: the runner
 * writes the report where gitleaks would, or writes nothing, and exits 0.
 *
 * <p><b>Exit 0 every time, deliberately.</b> A non-zero exit already throws; the defects pinned here
 * are the reports that end well and say nothing usable — and each of them used to resolve every
 * secret issue of the target.
 */
@DisplayName("the secrets scanner, reading its report")
class SecretsScannerTest {

    private static final String SECRET = "AKIAIOSFODNN7EXAMPLE";

    /** Runs the scanner with a container that leaves {@code report} behind, or nothing when null. */
    private static Optional<List<SecretsScanner.SecretFinding>> scanLeaving(String report, AtomicReference<Path> left) {
        ContainerRunner runner = mock(ContainerRunner.class);
        when(runner.run(any())).thenAnswer(call -> {
            ContainerRun run = call.getArgument(0);
            Path mounted = Path.of(run.mounts().getFirst().source());
            Path file = mounted.resolve("vectispire-gitleaks-report.json");
            left.set(file);
            if (report != null) {
                Files.writeString(file, report);
            }
            return new ContainerResult("", "", 0);
        });
        return Workspace.withWorkspace(workspace -> new SecretsScanner(runner, ScannerImages.PINNED.gitleaks())
                .scan(workspace, null));
    }

    @Test
    @DisplayName("a report gitleaks wrote is read, and the file is gone afterwards")
    void aReportIsRead() {
        AtomicReference<Path> left = new AtomicReference<>();

        Optional<List<SecretsScanner.SecretFinding>> found = scanLeaving(
                "[{\"RuleID\":\"aws-access-token\",\"File\":\"/repo/source/app.py\",\"StartLine\":3,\"Secret\":\""
                        + SECRET + "\"}]",
                left);

        assertThat(found).hasValueSatisfying(findings -> assertThat(findings).singleElement()
                .satisfies(finding -> assertThat(finding.file()).isEqualTo("app.py")));
        assertThat(left.get()).doesNotExist();
    }

    @Test
    @DisplayName("the empty array is a clean tree, the only one")
    void theEmptyArrayIsClean() {
        assertThat(scanLeaving("[]\n", new AtomicReference<>())).hasValue(List.of());
    }

    @Test
    @DisplayName("a report that is not gitleaks' fails the step, says why, and quotes nothing of it")
    void aCorruptReportFails() {
        AtomicReference<Path> left = new AtomicReference<>();

        // Truncated mid-way: the shape a full disk leaves, with the secret in the part that made it.
        assertThatThrownBy(() -> scanLeaving("[{\"RuleID\":\"aws-access-token\",\"Secret\":\"" + SECRET, left))
                .isInstanceOf(ScannerFailureException.class)
                .hasMessageContaining("not the JSON array of findings")
                // The message reaches the scan's failures, the screen and the exports; the file holds
                // the secrets in the clear, and a parser's message quotes what it choked on.
                .hasMessageNotContaining(SECRET);
        assertThat(left.get()).as("deleted on failure too").doesNotExist();
    }

    @Test
    @DisplayName("a report that is not even JSON fails the step, rather than reading as no secrets")
    void notJsonFails() {
        assertThatThrownBy(() -> scanLeaving("this is not json", new AtomicReference<>()))
                .isInstanceOf(ScannerFailureException.class);
    }

    @Test
    @DisplayName("no report at all fails the step: gitleaks v8.0 to v8.12 exit 0 without one when they cannot write it")
    void noReportFails() {
        // Measured: with the report path unwritable, v8.8.0 and v8.12.0 log "leaks found: 1" and exit 0
        // with no file, which this class read as "no secrets" — closing every secret issue of the target
        // on a run that had found one.
        assertThatThrownBy(() -> scanLeaving(null, new AtomicReference<>()))
                .isInstanceOf(ScannerFailureException.class)
                .hasMessageContaining("without writing its report");
    }
}
