package com.asmolabs.zanshin.common.domain.exports;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.zanshin.common.domain.issues.FindingType;
import com.asmolabs.zanshin.common.domain.issues.Severity;
import com.asmolabs.zanshin.common.domain.issues.TriageStatus;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("issue exports")
class ExportsTest {

    private static final Instant AT = Instant.parse("2026-08-10T08:00:00.000Z");
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static ExportableIssue.Builder issue() {
        return new ExportableIssue.Builder();
    }

    @Nested
    @DisplayName("OpenVEX")
    class Vex {

        @Test
        @DisplayName("only vulnerabilities with an identifier make a statement")
        void onlyIdentifiedVulnerabilities() {
            // VEX is defined over vulnerability identifiers. A hardcoded secret has no CVE to
            // make a statement about, and an anonymous statement is not a statement.
            List<ExportableIssue> issues = List.of(
                    issue().type(FindingType.VULNERABILITY).identifier("CVE-2024-1").build(),
                    issue().type(FindingType.SECRET).identifier("aws-key").build(),
                    issue().type(FindingType.VULNERABILITY).identifier(null).build());

            OpenVexDocument document = OpenVexExport.build(issues, options());

            assertThat(document.statements()).singleElement()
                    .satisfies(s -> assertThat(s.vulnerability().name()).isEqualTo("CVE-2024-1"));
        }

        @Test
        @DisplayName("under_review is spelled under_investigation, as the specification requires")
        void translatesUnderReview() {
            // The single divergence between Zanshin's triage vocabulary and OpenVEX's.
            OpenVexDocument document = OpenVexExport.build(
                    List.of(vulnerability().triageStatus(TriageStatus.UNDER_REVIEW).build()), options());

            assertThat(document.statements()).singleElement()
                    .satisfies(s -> assertThat(s.status()).isEqualTo("under_investigation"));
        }

        @Test
        @DisplayName("a resolved, never-triaged issue is stated as fixed, not as under investigation")
        void resolvedAndUntriagedIsFixed() {
            // The scanner stopped seeing it. Saying "under investigation" about something that
            // is gone would mislead in a document written to answer exactly that question.
            OpenVexDocument document = OpenVexExport.build(
                    List.of(vulnerability().resolved(true).build()), options());

            assertThat(document.statements()).singleElement()
                    .satisfies(s -> assertThat(s.status()).isEqualTo("fixed"));
        }

        @Test
        @DisplayName("not_affected carries its justification; affected carries an action statement")
        void freeTextGoesToTheRightField() {
            OpenVexDocument notAffected = OpenVexExport.build(
                    List.of(vulnerability()
                            .triageStatus(TriageStatus.NOT_AFFECTED)
                            .triageJustification("vulnerable_code_not_in_execute_path")
                            .triageComment("The parser is never reached.")
                            .build()),
                    options());
            OpenVexDocument affected = OpenVexExport.build(
                    List.of(vulnerability()
                            .triageStatus(TriageStatus.AFFECTED)
                            .triageComment("Scheduled for the next release.")
                            .build()),
                    options());

            assertThat(notAffected.statements().getFirst())
                    .satisfies(s -> {
                        assertThat(s.justification()).isEqualTo("vulnerable_code_not_in_execute_path");
                        assertThat(s.impactStatement()).isEqualTo("The parser is never reached.");
                        assertThat(s.actionStatement()).isNull();
                    });
            assertThat(affected.statements().getFirst())
                    .satisfies(s -> {
                        assertThat(s.actionStatement()).isEqualTo("Scheduled for the next release.");
                        assertThat(s.justification()).isNull();
                    });
        }

        @Test
        @DisplayName("serializes with the specification's key names, and omits what is absent")
        void serializesToTheSpecShape() throws Exception {
            String json = MAPPER.writeValueAsString(
                    OpenVexExport.build(List.of(vulnerability().build()), options()));
            JsonNode node = MAPPER.readTree(json);

            assertThat(node.get("@context").asText()).isEqualTo(OpenVexDocument.CONTEXT);
            assertThat(node.get("@id").asText()).isEqualTo("urn:zanshin:doc:1");
            // RFC 3339: a timestamp with no timezone is not a valid instant, and a strict
            // consumer is entitled to refuse the document.
            assertThat(node.get("timestamp").asText()).isEqualTo("2026-08-10T08:00:00.000Z");
            assertThat(node.get("statements").get(0).has("justification")).isFalse();
        }

        private static ExportableIssue.Builder vulnerability() {
            return issue().type(FindingType.VULNERABILITY).identifier("CVE-2024-1");
        }

        private static OpenVexExport.Options options() {
            return new OpenVexExport.Options("Zanshin", "pkg:generic/product", "urn:zanshin:doc:1", AT);
        }
    }

    @Nested
    @DisplayName("SARIF")
    class Sarif {

        @Test
        @DisplayName("every result has a location, even when the finding has no file")
        void alwaysHasALocation() {
            // GitHub silently discards results with no location. An honestly-empty location
            // would make the dependency findings vanish — that is, most of them.
            SarifLog log = SarifExport.build(
                    List.of(issue().type(FindingType.VULNERABILITY).identifier("CVE-1").filePath(null).build()),
                    new SarifExport.Options("api-service"));

            assertThat(log.runs().getFirst().results()).singleElement().satisfies(result ->
                    assertThat(result.locations().getFirst().physicalLocation().artifactLocation().uri())
                            .isEqualTo("."));
        }

        @Test
        @DisplayName("a triaged issue is suppressed, not removed")
        void triagedIssuesAreSuppressed() {
            // Removing it makes the platform report it as new on the next upload, undoing the
            // triage work. A suppression instead carries the reason it was set aside.
            SarifLog log = SarifExport.build(
                    List.of(issue().type(FindingType.VULNERABILITY).identifier("CVE-1")
                            .triageStatus(TriageStatus.NOT_AFFECTED)
                            .triageJustification("component_not_present")
                            .triagedBy("alice")
                            .build()),
                    new SarifExport.Options("api-service"));

            assertThat(log.runs().getFirst().results()).singleElement().satisfies(result -> {
                assertThat(result.suppressions()).singleElement().satisfies(suppression -> {
                    assertThat(suppression.kind()).isEqualTo("external");
                    assertThat(suppression.justification())
                            .contains("not_affected")
                            .contains("component_not_present")
                            .contains("decided by alice");
                });
            });
        }

        @Test
        @DisplayName("an issue judged affected is not suppressed")
        void affectedStaysVisible() {
            // Deciding an issue is real has to stay visible.
            SarifLog log = SarifExport.build(
                    List.of(issue().type(FindingType.VULNERABILITY).identifier("CVE-1")
                            .triageStatus(TriageStatus.AFFECTED).build()),
                    new SarifExport.Options("api-service"));

            assertThat(log.runs().getFirst().results().getFirst().suppressions()).isNull();
        }

        @Test
        @DisplayName("resolved issues are excluded entirely")
        void resolvedIssuesAreExcluded() {
            SarifLog log = SarifExport.build(
                    List.of(issue().type(FindingType.VULNERABILITY).identifier("CVE-1").resolved(true).build()),
                    new SarifExport.Options("api-service"));

            assertThat(log.runs().getFirst().results()).isEmpty();
        }

        @Test
        @DisplayName("rules are emitted once per identifier and indexed in order")
        void rulesAreDeduplicatedAndIndexed() {
            // A result pointing at the wrong index describes itself with another rule's title.
            SarifLog log = SarifExport.build(
                    List.of(
                            issue().type(FindingType.VULNERABILITY).identifier("CVE-1").build(),
                            issue().type(FindingType.SECRET).identifier("aws-key").build(),
                            issue().type(FindingType.VULNERABILITY).identifier("CVE-1").build()),
                    new SarifExport.Options("api-service"));

            SarifLog.Run run = log.runs().getFirst();
            assertThat(run.tool().driver().rules()).hasSize(2);
            assertThat(run.results()).extracting(SarifLog.Result::ruleIndex).containsExactly(0, 1, 0);
        }

        @Test
        @DisplayName("the rule id is partitioned by type, so two scanners cannot collide")
        void ruleIdsArePartitionedByType() {
            // A gitleaks rule and a checkov check can share an identifier; a platform indexed
            // on ruleId would merge two unrelated classes of issue under one title.
            SarifLog log = SarifExport.build(
                    List.of(
                            issue().type(FindingType.SECRET).identifier("generic-api-key").build(),
                            issue().type(FindingType.IAC).identifier("generic-api-key").build()),
                    new SarifExport.Options("api-service"));

            assertThat(log.runs().getFirst().tool().driver().rules())
                    .extracting(SarifLog.Rule::id)
                    .containsExactly("zanshin/secret/generic-api-key", "zanshin/iac/generic-api-key");
        }

        @ParameterizedTest(name = "{0} lands on a level a reviewer does not scroll past")
        @ValueSource(strings = {"CRITICAL", "HIGH"})
        void criticalAndHighAreErrors(String severity) {
            // SARIF has no "critical", and `warning` is what a reviewer scrolls past.
            SarifLog log = SarifExport.build(
                    List.of(issue().severity(Severity.valueOf(severity)).type(FindingType.VULNERABILITY).identifier("CVE-1").build()),
                    new SarifExport.Options("api-service"));

            assertThat(log.runs().getFirst().results().getFirst().level()).isEqualTo("error");
        }

        @Test
        @DisplayName("security-severity keeps a critical distinguishable from a high")
        void securitySeverityIsCarried() {
            // GitHub sorts and filters on this property, not on `level`.
            SarifLog log = SarifExport.build(
                    List.of(issue().severity(Severity.CRITICAL).type(FindingType.VULNERABILITY).identifier("CVE-1").build()),
                    new SarifExport.Options("api-service"));

            assertThat(log.runs().getFirst().tool().driver().rules().getFirst().properties())
                    .containsEntry("security-severity", "9.5");
        }

        @Test
        @DisplayName("an unknown severity gets no invented score")
        void unknownSeverityHasNoScore() {
            SarifLog log = SarifExport.build(
                    List.of(issue().severity(Severity.UNKNOWN).type(FindingType.VULNERABILITY).identifier("CVE-1").build()),
                    new SarifExport.Options("api-service"));

            assertThat(log.runs().getFirst().tool().driver().rules().getFirst().properties())
                    .doesNotContainKey("security-severity");
        }

        @Test
        @DisplayName("a quality finding is tagged quality, not security")
        void qualityIsNotTaggedSecurity() {
            SarifLog log = SarifExport.build(
                    List.of(issue().type(FindingType.QUALITY).identifier("long-method").build()),
                    new SarifExport.Options("api-service"));

            assertThat(log.runs().getFirst().tool().driver().rules().getFirst().properties())
                    .extracting("tags")
                    .asInstanceOf(org.assertj.core.api.InstanceOfAssertFactories.list(String.class))
                    .containsExactly("quality", "quality");
        }

        @Test
        @DisplayName("the message turns a CVE into an instruction")
        void messageSaysWhatToDo() {
            SarifLog log = SarifExport.build(
                    List.of(issue()
                            .type(FindingType.VULNERABILITY)
                            .identifier("CVE-2024-1")
                            .packageName("requests")
                            .packageVersion("2.31.0")
                            .fixVersions("2.32.0")
                            .kev(true)
                            .directDependency(false)
                            .build()),
                    new SarifExport.Options("api-service"));

            assertThat(log.runs().getFirst().results().getFirst().message().text())
                    .isEqualTo("requests 2.31.0 — CVE-2024-1 — fixed in 2.32.0 "
                            + "— known active exploitation (CISA KEV) — transitive dependency");
        }

        @Test
        @DisplayName("informationUri is absent rather than null when not supplied")
        void absentRatherThanNull() throws Exception {
            String json = MAPPER.writeValueAsString(SarifExport.build(List.of(), new SarifExport.Options("api-service")));

            assertThat(MAPPER.readTree(json).get("runs").get(0).get("tool").get("driver").has("informationUri"))
                    .isFalse();
        }
    }

    @Nested
    @DisplayName("CSV")
    class Csv {

        @Test
        @DisplayName("neutralizes a package name that a spreadsheet would execute")
        void neutralizesFormulas() {
            // The content comes from scanned repositories, hence from outside the trust
            // boundary; the reader is an operator opening the file in a spreadsheet. A package
            // named `=cmd|'/c calc'!A1` executes on open, with no prompt.
            String csv = IssueCsv.build(List.of(issue().packageName("=cmd|'/c calc'!A1").build()));

            // Not quoted: the value has no comma, quote or newline, so minimal quoting leaves
            // it bare. The apostrophe is what disarms it, and quoting was never the defence.
            assertThat(csv).contains(",'=cmd|'/c calc'!A1,");
        }

        @ParameterizedTest(name = "neutralizes a cell starting with {0}")
        @ValueSource(strings = {"=", "+", "-", "@", "\t", "\r"})
        void neutralizesEveryFormulaPrefix(String prefix) {
            // Tab and carriage return are in the list because Excel skips them before resuming
            // its parse: `\t=cmd|…` is evaluated as `=cmd|…`.
            String csv = IssueCsv.build(List.of(issue().packageName(prefix + "HYPERLINK(\"http://x\")").build()));

            assertThat(csv).contains("'" + prefix + "HYPERLINK");
        }

        @Test
        @DisplayName("quoting does not stand in for neutralization")
        void quotingIsNotProtection() {
            // A spreadsheet strips the quotes before evaluating, so the apostrophe has to be
            // inside them.
            String csv = IssueCsv.build(List.of(issue().packageName("=1+1,x").build()));

            assertThat(csv).contains("\"'=1+1,x\"").doesNotContain("\"=1+1,x\"");
        }

        @Test
        @DisplayName("the header names and the row values stay aligned")
        void headerAndValuesCannotDrift() {
            String csv = IssueCsv.build(List.of(issue().build()));
            String[] lines = csv.split("\r\n");

            assertThat(lines[0].split(",", -1)).hasSize(IssueCsv.Column.values().length);
            assertThat(lines[1].split(",", -1)).hasSize(IssueCsv.Column.values().length);
        }

        @Test
        @DisplayName("rows end with CRLF, including the last one")
        void rowsEndWithCrlf() {
            assertThat(IssueCsv.build(List.of(issue().build()))).endsWith("\r\n");
        }

        @Test
        @DisplayName("an unknown dependency kind is empty, not the word unknown")
        void unknownDependencyIsEmpty() {
            // A column filled with "unknown" reads as a finding about the dependency, when the
            // honest statement is that we have nothing to say about it.
            String csv = IssueCsv.build(List.of(issue().directDependency(null).build()));
            String[] header = csv.split("\r\n")[0].split(",");
            String[] row = csv.split("\r\n")[1].split(",", -1);

            int column = java.util.Arrays.asList(header).indexOf("dependency");
            assertThat(row[column]).isEmpty();
        }
    }
}
