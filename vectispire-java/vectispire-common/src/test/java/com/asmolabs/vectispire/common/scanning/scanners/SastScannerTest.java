package com.asmolabs.vectispire.common.scanning.scanners;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

@DisplayName("source code analysis")
class SastScannerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static JsonNode json(String text) {
        try {
            return MAPPER.readTree(text);
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    @Nested
    @DisplayName("deciding whether the analysis happened")
    class Coverage {

        @Test
        @DisplayName("zero files examined is not a clean tree")
        void zeroScannedIsNotClean() {
            // The hole this closes: the check used to return early on "no errors" before
            // looking at coverage, so a run that had excluded everything reported no findings
            // — hence "analysed, found nothing", hence the resolution of the target's whole
            // SAST and quality backlog.
            assertThat(SastScanner.mostlyFailed(json("{\"results\": [], \"errors\": [], \"paths\": {\"scanned\": []}}")))
                    .isTrue();
        }

        @Test
        @DisplayName("a report with no coverage information at all counts as not run")
        void missingCoverageIsNotRun() {
            // File selection is influenceable from the repository, so an absent `scanned` list
            // is exactly the shape an excluded-everything run takes.
            assertThat(SastScanner.mostlyFailed(json("{\"results\": []}"))).isTrue();
        }

        @Test
        @DisplayName("a clean run over real files is a clean run")
        void cleanRunIsAccepted() {
            assertThat(SastScanner.mostlyFailed(
                            json("{\"errors\": [], \"paths\": {\"scanned\": [\"a.py\", \"b.py\"]}}")))
                    .isFalse();
        }

        @Test
        @DisplayName("a few timeouts are tolerated, most of them are not")
        void toleratesSomeFailures() {
            // The tool exits 0 when individual files time out, so the exit code cannot tell a
            // mostly-skipped repository from a clean one.
            String tolerable = "{\"errors\": [1], \"paths\": {\"scanned\": [1,2,3,4,5,6,7,8,9,10]}}";
            String intolerable = "{\"errors\": [1,2,3,4,5], \"paths\": {\"scanned\": [1,2,3,4,5,6,7,8,9,10]}}";

            assertThat(SastScanner.mostlyFailed(json(tolerable))).isFalse();
            assertThat(SastScanner.mostlyFailed(json(intolerable))).isTrue();
        }
    }

    @Nested
    @DisplayName("reading the findings")
    class Findings {

        @ParameterizedTest(name = "{0} becomes {1}")
        @CsvSource({"ERROR, HIGH", "WARNING, MEDIUM", "INFO, LOW"})
        void mapsTheVocabularyExplicitly(String reported, String expected) {
            // An explicit table and not a lowercase conversion: "ERROR" lowercased is `error`,
            // which belongs to no policy threshold, and would propagate silently into the
            // ordering, the summary, the gate and the SARIF export.
            assertThat(SastScanner.severityOf(reported)).isEqualTo(Severity.valueOf(expected));
        }

        @Test
        @DisplayName("an unrecognized level defaults to medium, not to unknown")
        void unknownLevelsDefaultToMedium() {
            // UNKNOWN ranks below LOW, so defaulting there would quietly exempt a new level
            // from every gate.
            assertThat(SastScanner.severityOf("CRITICAL")).isEqualTo(Severity.MEDIUM);
            assertThat(SastScanner.severityOf(null)).isEqualTo(Severity.MEDIUM);
        }

        @Test
        @DisplayName("a finding with no category is security, not quality")
        void unknownCategoryIsSecurity() {
            // Filing an unknown finding as quality would make it unable to fail a gate, since
            // quality never blocks by design.
            JsonNode payload = json("""
                    {"results": [{"check_id": "rules.unknown", "path": "/repo/source/app.py",
                                  "start": {"line": 4}, "extra": {"message": "eval", "severity": "ERROR"}}]}""");

            assertThat(SastScanner.findings(payload, null)).singleElement().satisfies(finding -> {
                assertThat(finding.category()).isEqualTo("security");
                assertThat(finding.file()).isEqualTo("app.py");
                assertThat(finding.line()).isEqualTo(4);
                assertThat(finding.severity()).isEqualTo(Severity.HIGH);
            });
        }

        @Test
        @DisplayName("keeps the rule id exactly as reported")
        void ruleIdIsUntouched() {
            // It enters an issue's fingerprint. Normalizing it here — trimming a prefix,
            // lowercasing — would resolve the whole SAST backlog and recreate it from scratch.
            JsonNode payload = json("""
                    {"results": [{"check_id": "python.lang.security.audit.dangerous-eval",
                                  "path": "a.py", "extra": {}}]}""");

            assertThat(SastScanner.findings(payload, null).getFirst().ruleId())
                    .isEqualTo("python.lang.security.audit.dangerous-eval");
        }

        @Test
        @DisplayName("a report with no results is empty, not a failure")
        void noResultsIsEmpty() {
            assertThat(SastScanner.findings(json("{\"paths\": {\"scanned\": [\"a\"]}}"), null)).isEmpty();
        }
    }
}
