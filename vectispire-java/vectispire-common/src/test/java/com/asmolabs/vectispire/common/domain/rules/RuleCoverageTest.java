package com.asmolabs.vectispire.common.domain.rules;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * What an instance can actually see, and whether it says so.
 *
 * <p><b>The default install is the case under test.</b> Vectispire ships one Semgrep rule; an
 * estate scanned with it reports no findings, which every screen renders identically to code that
 * is clean. These assertions are about producing the one sentence that separates the two.
 */
@DisplayName("rule coverage")
class RuleCoverageTest {

    private static final List<String> BUNDLED_ONLY =
            List.of("gitleaks/gitleaks.toml", "semgrep/python/dangerous-eval.yaml");

    @Test
    @DisplayName("calls a fresh install unconfigured, whatever the estate contains")
    void aFreshInstallIsUnconfigured() {
        RuleCoverage.Assessment assessment = RuleCoverage.assess(
                BUNDLED_ONLY, List.of("pkg:maven/org.acme/thing@1.2", "pkg:npm/left-pad@1.0"));

        assertThat(assessment.state())
                .as("one pattern in one language is not a configuration, whatever is being scanned")
                .isEqualTo(RuleCoverage.State.UNCONFIGURED);
    }

    @Test
    @DisplayName("names the ecosystems a partial catalogue does not reach")
    void namesTheUncoveredEcosystems() {
        RuleCoverage.Assessment assessment = RuleCoverage.assess(
                List.of(
                        "semgrep/python/eval.yaml",
                        "semgrep/java/xss.yaml",
                        "semgrep/java/sqli.yaml"),
                List.of(
                        "pkg:maven/org.acme/thing@1.2",
                        "pkg:npm/left-pad@1.0",
                        "pkg:golang/github.com/acme/x@1.0"));

        assertThat(assessment.state()).isEqualTo(RuleCoverage.State.PARTIAL);
        assertThat(assessment.uncovered())
                .as("Java is covered; the other two are what the operator has to be told about")
                .containsExactlyInAnyOrder("npm", "golang");
    }

    @Test
    @DisplayName("raises nothing when every ecosystem present has rules")
    void raisesNothingWhenCovered() {
        RuleCoverage.Assessment assessment = RuleCoverage.assess(
                List.of("semgrep/python/eval.yaml", "semgrep/java/xss.yaml"),
                List.of("pkg:maven/org.acme/thing@1.2", "pkg:pypi/requests@2.0"));

        assertThat(assessment.state())
                .as("a warning shown when everything is fine loses its meaning within days")
                .isEqualTo(RuleCoverage.State.COVERED);
        assertThat(assessment.uncovered()).isEmpty();
    }

    @Test
    @DisplayName("does not blame the estate for a gap in its own mapping table")
    void doesNotBlameTheEstateForAnUnmappedEcosystem() {
        RuleCoverage.Assessment assessment = RuleCoverage.assess(
                List.of("semgrep/java/xss.yaml"),
                List.of("pkg:maven/org.acme/thing@1.2", "pkg:conan/zlib@1.3"));

        assertThat(assessment.ecosystemsInEstate()).contains("conan");
        assertThat(assessment.uncovered())
                .as("\"no rules for conan\" when nobody wrote the mapping is a defect reported as "
                        + "somebody else's")
                .isEmpty();
        assertThat(assessment.state()).isEqualTo(RuleCoverage.State.COVERED);
    }

    @Test
    @DisplayName("treats an estate with no inventory as unconfigured rather than covered")
    void anEmptyInventoryDoesNotEarnGreen() {
        assertThat(RuleCoverage.assess(BUNDLED_ONLY, List.of()).state())
                .as("nothing scanned and nothing configured is the same starting point, and the "
                        + "louder of the two readings is the useful one")
                .isEqualTo(RuleCoverage.State.UNCONFIGURED);
    }
}
