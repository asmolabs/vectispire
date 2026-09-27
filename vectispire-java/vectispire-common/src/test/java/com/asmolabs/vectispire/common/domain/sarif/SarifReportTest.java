package com.asmolabs.vectispire.common.domain.sarif;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.issues.Severity;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("reading a SARIF log")
class SarifReportTest {

    private static final long CAP = 1_000_000;

    private static SarifReport read(String json) {
        return SarifReport.read(json.getBytes(StandardCharsets.UTF_8), CAP, List.of("/repo/source"));
    }

    private static String log(String runs) {
        return "{\"version\":\"2.1.0\",\"runs\":[" + runs + "]}";
    }

    private static final String RUN = """
            {"tool":{"driver":{"name":"acme-lint","semanticVersion":"4.2.0","rules":[
                {"id":"ACME001","defaultConfiguration":{"level":"error"},"shortDescription":{"text":"Forbidden call"}},
                {"id":"ACME002","properties":{"security-severity":"9.1"}}]}},
             "results":[
                {"ruleId":"ACME001","message":{"text":"eval() here"},
                 "locations":[{"physicalLocation":{"artifactLocation":{"uri":"file:///repo/source/src/a.py"},"region":{"startLine":12}}}]},
                {"ruleIndex":1,"level":"note","locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/b.py","uriBaseId":"%SRCROOT%"}}}]},
                {"ruleId":"ACME003","kind":"pass"},
                {"ruleId":"ACME004","suppressions":[{"kind":"inSource"}]},
                {"ruleId":"ACME005","suppressions":[{"kind":"external","status":"rejected"}],"level":"warning"}
             ]}""";

    @Test
    @DisplayName("keeps the rule, the normalised path, the line, the message and a severity for each finding")
    void reads() {
        SarifReport.Run run = read(log(RUN)).runs().getFirst();

        assertThat(run.toolName()).isEqualTo("acme-lint");
        assertThat(run.toolVersion()).isEqualTo("4.2.0");
        assertThat(run.successful()).isTrue();
        assertThat(run.results()).hasValueSatisfying(findings -> assertThat(findings).containsExactly(
                new SarifFinding("ACME001", Severity.HIGH, "src/a.py", 12, "eval() here"),
                // The rule's security-severity outranks the result's own `note`.
                new SarifFinding("ACME002", Severity.CRITICAL, "src/b.py", null, null),
                new SarifFinding("ACME005", Severity.MEDIUM, null, null, null)));
    }

    @Test
    @DisplayName("a pass, a not-applicable and an accepted suppression are not findings")
    void notFindings() {
        SarifReport.Run run = read(log(RUN)).runs().getFirst();

        assertThat(run.results().orElseThrow()).extracting(SarifFinding::ruleId)
                .doesNotContain("ACME003", "ACME004");
    }

    @Test
    @DisplayName("a run without results did not compute any: absent, not an empty list")
    void absentIsNotEmpty() {
        SarifReport absent = read(log("{\"tool\":{\"driver\":{\"name\":\"t\"}}}"));
        SarifReport empty = read(log("{\"tool\":{\"driver\":{\"name\":\"t\"}},\"results\":[]}"));

        assertThat(absent.runs().getFirst().results()).isEmpty();
        assertThat(empty.runs().getFirst().results()).hasValue(List.of());
    }

    @Test
    @DisplayName("an invocation that says it failed is read as a failed run")
    void failedInvocation() {
        SarifReport report = read(log("{\"tool\":{\"driver\":{\"name\":\"t\"}},"
                + "\"invocations\":[{\"executionSuccessful\":false}],\"results\":[]}"));

        assertThat(report.runs().getFirst().successful()).isFalse();
    }

    @Test
    @DisplayName("SARIF's default level is warning, and error, note and none map to high, low and low")
    void levels() {
        assertThat(read(log("{\"tool\":{\"driver\":{\"name\":\"t\"}},\"results\":["
                        + "{\"ruleId\":\"a\"},{\"ruleId\":\"b\",\"level\":\"error\"},"
                        + "{\"ruleId\":\"c\",\"level\":\"note\"},{\"ruleId\":\"d\",\"level\":\"none\"},"
                        + "{\"ruleId\":\"e\",\"properties\":{\"security-severity\":7.0}},"
                        + "{\"ruleId\":\"f\",\"properties\":{\"security-severity\":\"not a score\"},\"level\":\"error\"}]}"))
                .runs().getFirst().results().orElseThrow())
                .extracting(SarifFinding::severity)
                .containsExactly(Severity.MEDIUM, Severity.HIGH, Severity.LOW, Severity.LOW, Severity.HIGH, Severity.HIGH);
    }

    @Test
    @DisplayName("a result naming no rule is refused: it has no identity across runs")
    void noRule() {
        assertThatThrownBy(() -> read(log("{\"tool\":{\"driver\":{\"name\":\"t\"}},\"results\":[{\"message\":{\"text\":\"x\"}}]}")))
                .isInstanceOf(InvalidSarifException.class)
                .hasMessageContaining("names no rule");
    }

    @Test
    @DisplayName("a run naming no tool is refused")
    void noTool() {
        assertThatThrownBy(() -> read(log("{\"tool\":{\"driver\":{}},\"results\":[]}")))
                .isInstanceOf(InvalidSarifException.class)
                .hasMessageContaining("tool.driver.name");
    }

    @Test
    @DisplayName("a document larger than the ceiling is refused before it is parsed")
    void tooLarge() {
        byte[] document = log(RUN).getBytes(StandardCharsets.UTF_8);

        assertThatThrownBy(() -> SarifReport.read(document, document.length - 1, List.of()))
                .isInstanceOf(InvalidSarifException.class)
                .hasMessageContaining("larger than");
    }

    @Test
    @DisplayName("a document that links to content held elsewhere is refused")
    void links() {
        assertThatThrownBy(() -> read("{\"version\":\"2.1.0\",\"inlineExternalProperties\":[{\"guid\":\"x\"}],\"runs\":[]}"))
                .isInstanceOf(InvalidSarifException.class)
                .hasMessageContaining("external");
        assertThatThrownBy(() -> read(log("{\"tool\":{\"driver\":{\"name\":\"t\"}},"
                        + "\"externalPropertyFileReferences\":{\"results\":[{\"location\":{\"uri\":\"https://x/r.json\"}}]}}")))
                .isInstanceOf(InvalidSarifException.class)
                .hasMessageContaining("external");
        assertThatThrownBy(() -> read(log("{\"tool\":{\"driver\":{\"name\":\"t\"}},\"results\":[{\"ruleId\":\"a\","
                        + "\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":\"https://evil/x.java\"}}}]}]}")))
                .isInstanceOf(InvalidSarifException.class)
                .hasMessageContaining("outside the analysed tree");
    }

    @Test
    @DisplayName("a document built to cost more to read than to send is refused: depth, duplicate keys, trailing content")
    void expansion() {
        String deep = "{\"version\":\"2.1.0\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"t\",\"x\":"
                + "[".repeat(200) + "]".repeat(200) + "}}}]}";
        assertThatThrownBy(() -> read(deep)).isInstanceOf(InvalidSarifException.class);

        assertThatThrownBy(() -> read("{\"version\":\"2.1.0\",\"version\":\"2.1.0\",\"runs\":[]}"))
                .isInstanceOf(InvalidSarifException.class)
                .hasMessageContaining("not readable");

        assertThatThrownBy(() -> read(log("") + "{}")).isInstanceOf(InvalidSarifException.class);
    }

    @Test
    @DisplayName("only SARIF 2.1.0 is read")
    void version() {
        assertThatThrownBy(() -> read("{\"version\":\"2.0.0\",\"runs\":[]}"))
                .isInstanceOf(InvalidSarifException.class)
                .hasMessageContaining("2.1.0");
    }

    @Test
    @DisplayName("a rule identifier carrying a NUL is refused: NUL is the fingerprint's field separator")
    void nulInRule() {
        assertThatThrownBy(() -> read(log("{\"tool\":{\"driver\":{\"name\":\"t\"}},\"results\":[{\"ruleId\":\"a\\u0000b\"}]}")))
                .isInstanceOf(InvalidSarifException.class);
    }

    @Test
    @DisplayName("more results than the ceiling are refused")
    void tooManyResults() {
        String result = "{\"ruleId\":\"a\"},";
        String many = result.repeat(SarifReport.MAX_RESULTS) + "{\"ruleId\":\"a\"}";

        assertThatThrownBy(() -> SarifReport.read(
                        log("{\"tool\":{\"driver\":{\"name\":\"t\"}},\"results\":[" + many + "]}").getBytes(StandardCharsets.UTF_8),
                        100_000_000, List.of()))
                .isInstanceOf(InvalidSarifException.class)
                .hasMessageContaining("results");
    }
}
