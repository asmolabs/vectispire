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
        @DisplayName("places a finding whose rule declares no 2021 category by its CWE, its own category first")
        void theCweWhenNoCategory() {
            JsonNode payload = json("""
                    {"results": [
                      {"check_id": "java.sqli", "path": "A.java", "start": {"line": 3},
                       "extra": {"metadata": {"cwe": ["CWE-89: Improper Neutralization of Special Elements"]}}},
                      {"check_id": "java.ssrf", "path": "B.java", "start": {"line": 5},
                       "extra": {"metadata": {"cwe": "CWE-918: Server-Side Request Forgery (SSRF)",
                                              "owasp": ["A01:2025 - Broken Access Control"]}}},
                      {"check_id": "java.both", "path": "C.java", "start": {"line": 7},
                       "extra": {"metadata": {"cwe": ["CWE-89: SQL injection"],
                                              "owasp": ["A01:2021 - Broken Access Control"]}}},
                      {"check_id": "java.style", "path": "D.java", "start": {"line": 9},
                       "extra": {"metadata": {"cwe": ["CWE-1078: Inappropriate Source Code Style"]}}}]}""");

            assertThat(SastScanner.findings(payload, null))
                    .extracting(SastScanner.SastFinding::owaspCategory)
                    .as("the CWE's category; the CWE beside a 2025 tag; the rule's own 2021 category over its "
                            + "CWE; a CWE no list holds places nothing")
                    .containsExactly("A03", "A10", "A01", null);
        }

        @Test
        @DisplayName("placing a finding by its CWE leaves every fingerprint input as it was")
        void theCweMovesNoFingerprint() {
            // AGENTS.md: the fingerprint is a data contract — rule id, path and type (IssueFingerprint).
            // The category is not among them, so a backlog scanned before and after this reads the same
            // issues, now placed.
            String result = """
                    {"results": [{"check_id": "java.sqli", "path": "/repo/source/A.java", "start": {"line": 3},
                                  "extra": {"message": "m", "severity": "ERROR"%s}}]}""";
            SastScanner.SastFinding before = SastScanner.findings(json(result.formatted("")), null).getFirst();
            SastScanner.SastFinding after = SastScanner.findings(
                    json(result.formatted(", \"metadata\": {\"cwe\": [\"CWE-89\"]}")), null).getFirst();

            assertThat(after.owaspCategory()).isEqualTo("A03");
            assertThat(after).usingRecursiveComparison().ignoringFields("owaspCategory").isEqualTo(before);
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
        @DisplayName("a report whose results are an empty array is a clean tree")
        void emptyResultsAreClean() {
            // What the pinned semgrep prints over a tree with nothing to report (measured).
            assertThat(SastScanner.findings(
                            json("{\"results\": [], \"errors\": [], \"paths\": {\"scanned\": [\"/repo/source/a.py\"]}}"),
                            null))
                    .isEmpty();
        }

        /**
         * <b>A report with no results is a failure, not an empty list.</b> It was pinned the other way
         * — "empty, not a failure" — and {@code mostlyFailed} lets such a payload through as soon as it
         * lists a scanned file, so a report of another shape resolved the target's SAST and quality
         * backlog. The pinned semgrep writes {@code "results": []} on a clean tree and on an empty one
         * (measured), so the old reading answered for no output the tool produces.
         */
        @ParameterizedTest(name = "{0}")
        @org.junit.jupiter.params.provider.ValueSource(strings = {
            "{\"paths\": {\"scanned\": [\"a\"]}}",
            "{\"results\": {}, \"paths\": {\"scanned\": [\"a\"]}}",
            "{\"results\": null, \"paths\": {\"scanned\": [\"a\"]}}",
            "{\"results\": [1, \"x\"], \"paths\": {\"scanned\": [\"a\"]}}"
        })
        @DisplayName("a report of another shape is thrown, never read as a clean tree")
        void anotherShapeFails(String payload) {
            org.assertj.core.api.Assertions.assertThatThrownBy(() -> SastScanner.findings(json(payload), null))
                    .isInstanceOf(com.asmolabs.vectispire.common.scanning.ScannerFailureException.class)
                    .hasMessageContaining("semgrep");
        }
    }
}
