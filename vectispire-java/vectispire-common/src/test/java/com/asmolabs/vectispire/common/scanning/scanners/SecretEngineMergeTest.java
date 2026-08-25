package com.asmolabs.vectispire.common.scanning.scanners;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.scanning.scanners.SecretsScanner.SecretFinding;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * What running two secret engines is supposed to mean.
 *
 * <p>The audit found the question unanswered: the product documentation promised "intelligent
 * multi-scanner deduplication", the code concatenated two lists, and the default configuration
 * ran the same engine twice. This suite is the decision, written down as assertions.
 *
 * <ol>
 *   <li>A second engine that is the same engine does not run at all.
 *   <li>When two real engines agree exactly, that is one finding.
 *   <li>When they disagree on the rule, that is two findings — deliberately.
 * </ol>
 */
@DisplayName("two secret engines")
class SecretEngineMergeTest {

    private static final String GITLEAKS = "zricethezav/gitleaks@sha256:aaa";
    private static final String OTHER = "example/other-engine@sha256:bbb";

    private static SecretFinding finding(String rule, String file, int line) {
        return new SecretFinding(rule, "an AWS key", file, line, "fp-" + rule + "-" + line);
    }

    @Test
    @DisplayName("the default configuration has no second engine, so nothing runs twice")
    void theDefaultAliasIsNotASecondEngine() {
        // `ScannerImages.PINNED` and the five-argument constructor both alias betterleaks to
        // gitleaks. Running it would analyse the tree twice for results equal by construction.
        assertThat(ScannerImages.PINNED.hasDistinctSecretEngines())
                .as("the pinned set aliases betterleaks to gitleaks — running it buys nothing")
                .isFalse();

        assertThat(new ScannerImages("syft", "grype", GITLEAKS, "checkov", "semgrep")
                        .hasDistinctSecretEngines())
                .as("the five-argument constructor aliases the two on purpose")
                .isFalse();
    }

    @Test
    @DisplayName("a genuinely different image is a second engine, and the seam exists for it")
    void adifferentImageIsASecondEngine() {
        assertThat(new ScannerImages("syft", "grype", GITLEAKS, OTHER, "checkov", "semgrep")
                        .hasDistinctSecretEngines())
                .isTrue();
    }

    @Test
    @DisplayName("the same secret reported identically by both is one finding")
    void identicalFindingsCollapse() {
        // Not tidiness: `IssueSyncService` increments `times_seen` once per finding, so a
        // duplicate inside a single scan makes an issue look twice as persistent as it is.
        SecretFinding shared = finding("aws-access-key", "src/app.py", 12);

        List<SecretFinding> merged = SecretsScanner.merge(
                List.of(shared, finding("generic-api-key", "src/db.py", 40)),
                List.of(shared));

        assertThat(merged).hasSize(2);
        assertThat(merged).containsExactly(shared, finding("generic-api-key", "src/db.py", 40));
    }

    @Test
    @DisplayName("the same line under two different rule names stays two findings, deliberately")
    void disagreementIsKept() {
        // Collapsing these would mean choosing which engine's rule identity survives, and that
        // identity is what tells an analyst why the line was flagged. Two engines disagreeing is
        // information. The cost — `IssueFingerprint` includes the rule id, so this becomes two
        // issues — is the reason the redundant default pass is skipped rather than deduplicated.
        List<SecretFinding> merged = SecretsScanner.merge(
                List.of(finding("aws-access-key", "src/app.py", 12)),
                List.of(finding("cloud-credential", "src/app.py", 12)));

        assertThat(merged)
                .as("a disagreement between two engines is not a duplicate")
                .hasSize(2);
    }

    @Test
    @DisplayName("the primary engine's results come first")
    void orderIsPreserved() {
        SecretFinding primary = finding("aws-access-key", "a.py", 1);
        SecretFinding secondary = finding("other-rule", "b.py", 2);

        assertThat(SecretsScanner.merge(List.of(primary), List.of(secondary)))
                .containsExactly(primary, secondary);
    }
}
