package com.asmolabs.vectispire.common.domain.checklists;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("a checklist rule")
class ChecklistRuleTest {

    @Test
    @DisplayName("reads the ADR's example binding and writes one canonical form, keys sorted, ratios as decimals")
    void theCanonicalForm() {
        ChecklistRule rule = ChecklistRule.parse("""
                {"kind":"findings_threshold","maxAgeDays":7,
                 "scopes":["import:quality-server/SonarQube","builtin:sast"],
                 "thresholds":{"medium":{"minResolvedRatio":0.60},"critical":{"maxOpen":0},"high":{"maxOpen":2}}}""");

        assertThat(rule).isInstanceOfSatisfying(ChecklistRule.FindingsThreshold.class, findings -> {
            assertThat(findings.scopes()).extracting(ToolScope::key)
                    .containsExactly("builtin:sast", "import:quality-server/sonarqube");
            assertThat(findings.thresholds().get(Severity.MEDIUM).minResolvedRatio()).contains(new BigDecimal("0.6"));
        });
        String canonical = rule.canonical();
        assertThat(canonical).isEqualTo("{\"kind\":\"findings_threshold\",\"maxAgeDays\":7,\"scopes\":[\"builtin:sast\","
                + "\"import:quality-server/sonarqube\"],\"thresholds\":{\"critical\":{\"maxOpen\":0},\"high\":{\"maxOpen\":2},"
                + "\"medium\":{\"minResolvedRatio\":0.6}}}");
        // Read back, the same bytes: the digest of an item is computed over this and must not move.
        assertThat(ChecklistRule.fromCanonical(canonical).canonical()).isEqualTo(canonical);
        assertThat(ChecklistRule.fromCanonical(canonical).digest()).isEqualTo(rule.digest());
    }

    @Test
    @DisplayName("refuses a rule without its maximum age, and every age outside a day to a year and a day")
    void aMaximumAgeIsRequired() {
        assertThatThrownBy(() -> ChecklistRule.parse("{\"kind\":\"coverage_threshold\",\"metric\":\"line\","
                + "\"minimumRatio\":0.8,\"aggregation\":\"per_repository\"}"))
                .isInstanceOf(InvalidInputException.class).hasMessageContaining("maxAgeDays");
        assertThatThrownBy(() -> new ChecklistRule.TestSuitePassed(0, "*", 1)).isInstanceOf(InvalidInputException.class);
        assertThatThrownBy(() -> new ChecklistRule.TestSuitePassed(367, "*", 1)).isInstanceOf(InvalidInputException.class);
        assertThat(new ChecklistRule.TestSuitePassed(366, "*", 1).maxAgeDays()).isEqualTo(366);
    }

    @Test
    @DisplayName("states what no product default may decide: the schedule question, a findings threshold")
    void nothingIsAssumed() {
        assertThatThrownBy(() -> ChecklistRule.parse("{\"kind\":\"dependency_analysis\",\"maxAgeDays\":7}"))
                .isInstanceOf(InvalidInputException.class).hasMessageContaining("requireSchedule");
        assertThatThrownBy(() -> ChecklistRule.parse("{\"kind\":\"findings_threshold\",\"maxAgeDays\":7,"
                + "\"scopes\":[\"builtin:secret\"]}"))
                .isInstanceOf(InvalidInputException.class).hasMessageContaining("threshold");
        assertThatThrownBy(() -> ChecklistRule.parse("{\"kind\":\"findings_threshold\",\"maxAgeDays\":7,"
                + "\"scopes\":[\"builtin:secret\"],\"thresholds\":{\"high\":{}}}"))
                .isInstanceOf(InvalidInputException.class).hasMessageContaining("maxOpen, minResolvedRatio or both");
    }

    @Test
    @DisplayName("refuses a parameter another kind takes, rather than ignoring it")
    void aForeignParameterIsRefused() {
        assertThatThrownBy(() -> ChecklistRule.parse("{\"kind\":\"test_suite_passed\",\"maxAgeDays\":7,"
                + "\"suitePattern\":\"*\",\"minimumTests\":1,\"metric\":\"line\"}"))
                .isInstanceOf(InvalidInputException.class).hasMessageContaining("takes no \"metric\"");
    }

    @Test
    @DisplayName("names its scopes as the fingerprint keys them, and refuses one nothing examines")
    void scopes() {
        assertThat(ToolScope.parse("builtin:secret")).isEqualTo(new ToolScope.BuiltIn(FindingType.SECRET));
        assertThat(ToolScope.parse("plugin:java-arch").key()).isEqualTo("plugin:java-arch");
        assertThat(ToolScope.parse("import:ledger-ci/ESLint").key()).isEqualTo("import:ledger-ci/eslint");
        assertThatThrownBy(() -> ToolScope.parse("builtin:plugin")).isInstanceOf(InvalidInputException.class);
        assertThatThrownBy(() -> ToolScope.parse("builtin:ai_review")).isInstanceOf(InvalidInputException.class);
        assertThatThrownBy(() -> ToolScope.parse("plugin:Bad_Id")).isInstanceOf(InvalidInputException.class);
        assertThatThrownBy(() -> ToolScope.parse("import:ledger-ci")).isInstanceOf(InvalidInputException.class);
        assertThatThrownBy(() -> ToolScope.parse("sast")).isInstanceOf(InvalidInputException.class);
        assertThatThrownBy(() -> ChecklistRule.parse("{\"kind\":\"findings_threshold\",\"maxAgeDays\":7,"
                + "\"scopes\":[\"builtin:sast\",\"builtin:sast\"],\"thresholds\":{\"high\":{\"maxOpen\":0}}}"))
                .isInstanceOf(InvalidInputException.class).hasMessageContaining("twice");
    }

    @Test
    @DisplayName("keeps a ratio decimal, within [0, 1] and four decimals")
    void ratios() {
        assertThatThrownBy(() -> new SeverityThreshold(Optional.empty(), Optional.of(new BigDecimal("1.2"))))
                .isInstanceOf(InvalidInputException.class);
        assertThatThrownBy(() -> new SeverityThreshold(Optional.empty(), Optional.of(new BigDecimal("0.12345"))))
                .isInstanceOf(InvalidInputException.class);
        assertThat(new SeverityThreshold(Optional.empty(), Optional.of(new BigDecimal("1.000"))).minResolvedRatio())
                .contains(new BigDecimal("1"));
        assertThatThrownBy(() -> new ChecklistRule.CoverageThreshold(7, ChecklistRule.Metric.LINE, BigDecimal.ZERO,
                ChecklistRule.Aggregation.PER_REPOSITORY)).as("at least nothing covered is no rule")
                .isInstanceOf(InvalidInputException.class);
        assertThat(Ratios.atLeast(3, 5, new BigDecimal("0.6"))).as("exactly, where a double would round").isTrue();
        assertThat(Ratios.atLeast(2, 5, new BigDecimal("0.6"))).isFalse();
    }

    @Test
    @DisplayName("declares packages by a package-URL prefix and allowed versions, and nothing else")
    void components() {
        ChecklistRule rule = ChecklistRule.parse("""
                {"kind":"component_versions","maxAgeDays":30,"components":[
                  {"purlPrefix":"pkg:maven/com.example/ledger-core","versions":["3.2.1","3.1.0","3.2.1"]}]}""");
        assertThat(rule.canonical()).isEqualTo("{\"components\":[{\"purlPrefix\":\"pkg:maven/com.example/ledger-core\","
                + "\"versions\":[\"3.1.0\",\"3.2.1\"]}],\"kind\":\"component_versions\",\"maxAgeDays\":30}");

        AllowedComponent allowed = new AllowedComponent("pkg:npm/left", List.of("1.0.0"));
        assertThat(allowed.names("pkg:npm/left@1.0.0")).isTrue();
        assertThat(allowed.names("pkg:npm/left-pad@1.0.0")).as("a prefix ends at a boundary").isFalse();
        assertThatThrownBy(() -> new AllowedComponent("pkg:npm/left@1.0.0", List.of("1.0.0")))
                .as("a version belongs in the list, not the prefix").isInstanceOf(InvalidInputException.class);
        assertThatThrownBy(() -> new AllowedComponent("maven:com.example", List.of("1")))
                .isInstanceOf(InvalidInputException.class);
        assertThatThrownBy(() -> new AllowedComponent("pkg:npm/left", List.of())).isInstanceOf(InvalidInputException.class);
    }

    @Test
    @DisplayName("keeps a rule bound before ranges and presence byte for byte, and its digest")
    void aRuleBoundBeforeKeepsItsDigest() {
        // Pinned: the text a line bound with exact versions stores, and the digest its content digest reads.
        // A change of the writing marks every such line changed in the next version (decision 0032 §4).
        String stored = "{\"components\":[{\"purlPrefix\":\"pkg:maven/com.example/ledger-core\","
                + "\"versions\":[\"3.1.0\",\"3.2.1\"]}],\"kind\":\"component_versions\",\"maxAgeDays\":30}";
        ChecklistRule read = ChecklistRule.fromCanonical(stored);
        assertThat(read.canonical()).isEqualTo(stored);
        assertThat(read.digest()).isEqualTo("6be6a79d0b5e485bb2c34d6d5bca78ac5864c149b87a0fe8eda08ba2249e85be");
        assertThat(ChecklistRule.parse("""
                {"kind":"component_versions","maxAgeDays":30,"components":[
                  {"purlPrefix":"pkg:maven/com.example/ledger-core","versions":["3.2.1","3.1.0"]}]}""").digest())
                .isEqualTo(read.digest());
    }

    @Test
    @DisplayName("binds Maven ranges beside exact versions, as written, and refuses a range that does not read in words")
    void ranges() {
        ChecklistRule rule = ChecklistRule.parse("""
                {"kind":"component_versions","maxAgeDays":7,"components":[
                  {"purlPrefix":"pkg:maven/org.example.platform","versions":["[1.17,2.0)","1.16.4","(,1.0],[1.2,1.3)"]}]}""");
        assertThat(rule.canonical()).isEqualTo("{\"components\":[{\"purlPrefix\":\"pkg:maven/org.example.platform\","
                + "\"versions\":[\"(,1.0],[1.2,1.3)\",\"1.16.4\",\"[1.17,2.0)\"]}],\"kind\":\"component_versions\","
                + "\"maxAgeDays\":7}");
        assertThat(ChecklistRule.fromCanonical(rule.canonical()).canonical()).isEqualTo(rule.canonical());
        AllowedComponent family = ((ChecklistRule.ComponentVersions) rule).components().getFirst();
        assertThat(family.allows("1.18.3")).isTrue();
        assertThat(family.allows("1.16.4")).isTrue();
        assertThat(family.allows("1.16.5")).isFalse();
        assertThat(family.allows("1.2.9")).isTrue();
        assertThat(family.allows("1.1")).isFalse();

        assertThatThrownBy(() -> ChecklistRule.parse("""
                {"kind":"component_versions","maxAgeDays":7,"components":[
                  {"purlPrefix":"pkg:maven/org.example.platform","versions":["[2.0,1.17)"]}]}"""))
                .isInstanceOf(InvalidInputException.class)
                .hasMessage("The version range \"[2.0,1.17)\" does not read: its lower bound 2.0 is above its upper"
                        + " bound 1.17.");
        assertThatThrownBy(() -> ChecklistRule.parse("""
                {"kind":"component_versions","maxAgeDays":7,"components":[
                  {"purlPrefix":"pkg:maven/org.example.platform","versions":["[1.17,2.0"]}]}"""))
                .isInstanceOf(InvalidInputException.class).hasMessageContaining("closes with ] or )");
        assertThatThrownBy(() -> ChecklistRule.parse("""
                {"kind":"component_versions","maxAgeDays":7,"components":[
                  {"purlPrefix":"pkg:npm/left-pad","versions":["[1.0,2.0)"]}]}"""))
                .as("npm orders its versions its own way; only Maven's order is implemented")
                .isInstanceOf(InvalidInputException.class)
                .hasMessageContaining("applies to a pkg:maven/ package only; pkg:npm/left-pad is not one");

        // Stored before ranges existed, on another type: read back as the literal it was, never refused.
        String literal = "{\"components\":[{\"purlPrefix\":\"pkg:npm/left-pad\",\"versions\":[\"[1.0,2.0)\"]}],"
                + "\"kind\":\"component_versions\",\"maxAgeDays\":7}";
        AllowedComponent stored = ((ChecklistRule.ComponentVersions) ChecklistRule.fromCanonical(literal))
                .components().getFirst();
        assertThat(stored.allows("1.5.0")).isFalse();
        assertThat(stored.allows("[1.0,2.0)")).isTrue();
    }

    @Test
    @DisplayName("binds a presence rule as prefixes alone, and refuses versions, a separator ending and a duplicate")
    void presence() {
        ChecklistRule rule = ChecklistRule.parse("""
                {"kind":"component_present","maxAgeDays":30,"components":[
                  {"purlPrefix":"pkg:maven/org.example.platform/platform-application"},
                  {"purlPrefix":" pkg:maven/org.example.platform "}]}""");
        assertThat(rule.canonical()).isEqualTo("{\"components\":[{\"purlPrefix\":\"pkg:maven/org.example.platform\"},"
                + "{\"purlPrefix\":\"pkg:maven/org.example.platform/platform-application\"}],"
                + "\"kind\":\"component_present\",\"maxAgeDays\":30}");
        assertThat(ChecklistRule.fromCanonical(rule.canonical()).canonical()).isEqualTo(rule.canonical());
        assertThat(rule.digest()).as("another kind, another digest than the same prefix's component_versions")
                .isNotEqualTo(ChecklistRule.parse("""
                        {"kind":"component_versions","maxAgeDays":30,"components":[
                          {"purlPrefix":"pkg:maven/org.example.platform","versions":["1.0"]}]}""").digest());

        assertThatThrownBy(() -> ChecklistRule.parse("""
                {"kind":"component_present","maxAgeDays":30,"components":[
                  {"purlPrefix":"pkg:maven/org.example.platform","versions":["1.0"]}]}"""))
                .isInstanceOf(InvalidInputException.class)
                .hasMessage("A component_present rule asks for a package whatever its version, and "
                        + "pkg:maven/org.example.platform lists versions — bind component_versions to judge them.");
        assertThatThrownBy(() -> ChecklistRule.parse("""
                {"kind":"component_present","maxAgeDays":30,"components":[{"purlPrefix":"pkg:maven/org.example/"}]}"""))
                .isInstanceOf(InvalidInputException.class).hasMessageContaining("Write \"pkg:maven/org.example\"");
        assertThat(ChecklistRule.fromCanonical("{\"components\":[{\"purlPrefix\":\"pkg:maven/org.example/\"}],"
                + "\"kind\":\"component_present\",\"maxAgeDays\":30}").canonical())
                .as("a stored one reads back, its text its digest").contains("pkg:maven/org.example/");
        assertThatThrownBy(() -> ChecklistRule.parse("""
                {"kind":"component_present","maxAgeDays":30,"components":[
                  {"purlPrefix":"pkg:maven/org.example"},{"purlPrefix":"pkg:maven/org.example "}]}"""))
                .isInstanceOf(InvalidInputException.class).hasMessage("The package pkg:maven/org.example is declared twice.");
        assertThatThrownBy(() -> ChecklistRule.parse("""
                {"kind":"component_present","maxAgeDays":30,"components":[]}"""))
                .isInstanceOf(InvalidInputException.class).hasMessageContaining("1 to 50 packages");
        assertThatThrownBy(() -> ChecklistRule.parse("""
                {"kind":"component_present","maxAgeDays":30,"components":[{"purlPrefix":"pkg:maven/a","pinned":true}]}"""))
                .isInstanceOf(InvalidInputException.class).hasMessageContaining("\"pinned\" is not one");
        assertThatThrownBy(() -> ChecklistRule.parse("""
                {"kind":"component_present","maxAgeDays":30,"components":[{"purlPrefix":"pkg:maven/a@1.0"}]}"""))
                .isInstanceOf(InvalidInputException.class).hasMessageContaining("without its version");
    }

    @Test
    @DisplayName("refuses a prefix ending on its separator when bound, naming the prefix that works, and reads a stored one unchanged")
    void aPrefixEndingOnItsSeparator() {
        String stated = """
                {"kind":"component_versions","maxAgeDays":30,"components":[
                  {"purlPrefix":"pkg:maven/com.example.tools/","versions":["1.0.0"]}]}""";
        assertThatThrownBy(() -> ChecklistRule.parse(stated))
                .as("it matched nothing: names() expects the separator after the prefix")
                .isInstanceOf(InvalidInputException.class)
                .hasMessageContaining("\"pkg:maven/com.example.tools/\" names no package")
                .hasMessageContaining("Write \"pkg:maven/com.example.tools\"");

        // A line bound before the refusal: its stored text is its digest, so reading it back neither
        // refuses nor rewrites it.
        String stored = "{\"components\":[{\"purlPrefix\":\"pkg:maven/com.example.tools/\",\"versions\":[\"1.0.0\"]}],"
                + "\"kind\":\"component_versions\",\"maxAgeDays\":30}";
        ChecklistRule read = ChecklistRule.fromCanonical(stored);
        assertThat(read.canonical()).isEqualTo(stored);

        ChecklistRule fixed = ChecklistRule.parse(stated.replace("tools/", "tools"));
        AllowedComponent namespace = ((ChecklistRule.ComponentVersions) fixed).components().getFirst();
        assertThat(namespace.names("pkg:maven/com.example.tools/cli@1.0.0")).as("the fix names the namespace").isTrue();
        assertThat(namespace.names("pkg:maven/com.example.toolsmith/cli@1.0.0")).isFalse();
    }

    @Test
    @DisplayName("keeps a one-pattern test rule byte for byte, and writes several sorted and once, under their own key")
    void severalSuitePatterns() {
        // What a rule bound before several patterns existed was stored as: it must read back to the same bytes.
        String stored = "{\"kind\":\"test_suite_passed\",\"maxAgeDays\":7,\"minimumTests\":1,\"suitePattern\":\"*Test\"}";
        assertThat(ChecklistRule.fromCanonical(stored).canonical()).isEqualTo(stored);
        assertThat(ChecklistRule.parse("{\"kind\":\"test_suite_passed\",\"maxAgeDays\":7,\"minimumTests\":1,"
                + "\"suitePatterns\":[\"*Test\"]}").canonical()).as("one pattern in a list is the one-pattern rule")
                .isEqualTo(stored);

        ChecklistRule both = ChecklistRule.parse("{\"kind\":\"test_suite_passed\",\"maxAgeDays\":7,\"minimumTests\":1,"
                + "\"suitePatterns\":[\" *Test\",\"*IT\",\"*Test\"]}");
        String canonical = "{\"kind\":\"test_suite_passed\",\"maxAgeDays\":7,\"minimumTests\":1,"
                + "\"suitePatterns\":[\"*IT\",\"*Test\"]}";
        assertThat(both.canonical()).isEqualTo(canonical);
        assertThat(ChecklistRule.fromCanonical(canonical).digest()).isEqualTo(both.digest());
        assertThat(ChecklistRule.parse("{\"kind\":\"test_suite_passed\",\"maxAgeDays\":7,\"minimumTests\":1,"
                + "\"suitePatterns\":[\"*IT\",\"*Test\"]}").digest()).as("the order typed is not the rule").isEqualTo(both.digest());

        assertThatThrownBy(() -> ChecklistRule.parse("{\"kind\":\"test_suite_passed\",\"maxAgeDays\":7,\"minimumTests\":1,"
                + "\"suitePattern\":\"*Test\",\"suitePatterns\":[\"*IT\"]}"))
                .isInstanceOf(InvalidInputException.class).hasMessageContaining("not both");
        assertThatThrownBy(() -> ChecklistRule.parse("{\"kind\":\"test_suite_passed\",\"maxAgeDays\":7,\"minimumTests\":1,"
                + "\"suitePatterns\":[]}"))
                .isInstanceOf(InvalidInputException.class).hasMessageContaining("1 to 10 suite patterns");
        assertThatThrownBy(() -> ChecklistRule.parse("{\"kind\":\"test_suite_passed\",\"maxAgeDays\":7,\"minimumTests\":1,"
                + "\"suitePatterns\":[\"*Test\",\" \"]}"))
                .isInstanceOf(InvalidInputException.class).hasMessageContaining("A suite pattern names the suites");
        assertThatThrownBy(() -> ChecklistRule.parse("{\"kind\":\"test_suite_passed\",\"maxAgeDays\":7,\"minimumTests\":1,"
                + "\"suitePatterns\":[\"*Test\",3]}"))
                .isInstanceOf(InvalidInputException.class).hasMessageContaining("is a string");
        assertThatThrownBy(() -> new ChecklistRule.TestSuitePassed(7, List.of("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"), 1))
                .isInstanceOf(InvalidInputException.class);
        assertThatThrownBy(() -> ChecklistRule.parse("{\"kind\":\"test_suite_passed\",\"maxAgeDays\":7,\"minimumTests\":1}"))
                .as("a rule naming no suite").isInstanceOf(InvalidInputException.class).hasMessageContaining("suite pattern");
    }

    @Test
    @DisplayName("matches a suite's whole name with * and ?, and nothing else as a wildcard")
    void suitePatterns() {
        SuitePattern arch = SuitePattern.of("com.example.arch.*Test");
        assertThat(arch.matches("com.example.arch.LayersTest")).isTrue();
        assertThat(arch.matches("com.example.arch.LayersTests")).isFalse();
        assertThat(arch.matches("comXexample.arch.LayersTest")).as("a dot is a dot").isFalse();
        assertThat(SuitePattern.of("Suite?").matches("Suite1")).isTrue();
        assertThat(SuitePattern.of("Suite?").matches("Suite")).isFalse();
        assertThat(SuitePattern.of("*").matches("")).isTrue();
        assertThat(SuitePattern.of("a*b*c").matches("aXbYbZc")).isTrue();
    }
}
