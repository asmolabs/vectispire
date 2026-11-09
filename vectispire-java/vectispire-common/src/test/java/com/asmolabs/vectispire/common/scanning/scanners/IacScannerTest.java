package com.asmolabs.vectispire.common.scanning.scanners;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.asmolabs.vectispire.common.scanning.ContainerRunner;
import com.asmolabs.vectispire.common.scanning.ContainerRunner.ContainerResult;
import com.asmolabs.vectispire.common.scanning.Workspace;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The IaC checker's report, through {@link IacScanner#scan} with the container replaced by what it
 * printed.
 *
 * <p>The three clean shapes are checkov 3.3.9's own output (the pinned image, run on a tree with
 * nothing to check, on one Terraform file, and on Terraform, CloudFormation, a Dockerfile and a
 * workflow together), trimmed to two failed checks a report. Every other shape used to end in an
 * empty list, which resolved the target's whole IaC backlog.
 */
@DisplayName("the IaC checker's report")
class IacScannerTest {

    private static Optional<List<IacScanner.IacFinding>> scanPrinting(String stdout) {
        ContainerRunner runner = mock(ContainerRunner.class);
        when(runner.run(any())).thenReturn(new ContainerResult(stdout, "", 0));
        return Workspace.withWorkspace(workspace ->
                new IacScanner(runner, ScannerImages.PINNED.checkov()).scan(workspace, null));
    }

    @Test
    @DisplayName("the bare summary checkov prints when there is nothing to check is a clean tree")
    void nothingToCheckIsClean() {
        assertThat(scanPrinting(DependencyScannerTest.fixture("checkov-3.3.9-nothing-to-check.json")))
                .hasValue(List.of());
    }

    @Test
    @DisplayName("one framework's report is read")
    void oneFramework() {
        assertThat(scanPrinting(DependencyScannerTest.fixture("checkov-3.3.9-one-framework.json")))
                .hasValueSatisfying(findings -> assertThat(findings).hasSize(2)
                        .allSatisfy(finding -> assertThat(finding.file()).isEqualTo("main.tf")));
    }

    @Test
    @DisplayName("several frameworks' reports are read together, those with nothing failed included")
    void severalFrameworks() {
        assertThat(scanPrinting(DependencyScannerTest.fixture("checkov-3.3.9-several-frameworks.json")))
                .hasValueSatisfying(findings -> assertThat(findings).extracting(IacScanner.IacFinding::file)
                        .containsExactlyInAnyOrder("main.tf", "main.tf", "Dockerfile", "Dockerfile",
                                ".github/workflows/ci.yml", ".github/workflows/ci.yml"));
    }

    @ParameterizedTest(name = "{0}")
    @ValueSource(strings = {
        // An object that is neither a report nor the bare summary.
        "{}",
        "{\"passed\": 0, \"failed\": 0}",
        // A report whose results are missing or of another shape.
        "{\"check_type\": \"terraform\", \"results\": {}, \"summary\": {}}",
        "{\"check_type\": \"terraform\", \"results\": {\"failed_checks\": {}}}",
        "{\"check_type\": \"terraform\", \"results\": null}",
        "{\"check_type\": \"terraform\", \"results\": {\"failed_checks\": [1, \"x\"]}}",
        // A list of reports with nothing in it, or one element that is not a report.
        "[]",
        "[{\"check_type\": \"terraform\", \"results\": {\"failed_checks\": []}}, \"text\"]",
        // JSON, but not an object or a list.
        "\"text\"",
        "42"
    })
    @DisplayName("a payload of another shape is absent, never an empty list")
    void anotherShapeIsAbsent(String stdout) {
        assertThat(scanPrinting(stdout)).isEmpty();
    }
}
