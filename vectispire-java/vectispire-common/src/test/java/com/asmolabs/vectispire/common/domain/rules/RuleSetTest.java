package com.asmolabs.vectispire.common.domain.rules;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.IntStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

@DisplayName("Semgrep rule sets")
class RuleSetTest {

    private static RuleSet.UploadedFile file(String name, String content) {
        return new RuleSet.UploadedFile(name, content);
    }

    @Nested
    @DisplayName("accepting an upload")
    class Accept {

        @Test
        @DisplayName("renames every file, so there is no path to escape from")
        void renamesFiles() {
            // Path traversal is removed as a class rather than filtered for: the uploaded name
            // is recorded for display and never used as a path.
            List<RuleSet.StoredFile> stored = RuleSet.accept(List.of(
                    file("../../../etc/passwd.yaml", "rules: []\n"), file("ok.yml", "rules: []\n")));

            assertThat(stored).extracting(RuleSet.StoredFile::path).containsExactly("rule-0001.yaml", "rule-0002.yaml");
            assertThat(stored.getFirst().originalName()).isEqualTo("../../../etc/passwd.yaml");
        }

        @ParameterizedTest(name = "refuses [{0}], which is not a rule file")
        @ValueSource(strings = {"rules.txt", "rules", "rules.yaml.exe", ""})
        void refusesNonYaml(String name) {
            assertThatThrownBy(() -> RuleSet.accept(List.of(file(name, "rules: []\n"))))
                    .isInstanceOf(InvalidRuleSetException.class);
        }

        @Test
        @DisplayName("throws rather than storing a subset")
        void refusesRatherThanFiltering() {
            // An operator who uploaded forty files and got thirty-eight stored would have
            // coverage they believe they have and do not.
            assertThatThrownBy(() -> RuleSet.accept(List.of(file("a.yaml", "rules: []\n"), file("b.txt", "x"))))
                    .isInstanceOf(InvalidRuleSetException.class);
        }

        @Test
        @DisplayName("refuses an empty file, an empty upload and one over the caps")
        void enforcesTheCaps() {
            assertThatThrownBy(() -> RuleSet.accept(List.of())).hasMessageContaining("No file");
            assertThatThrownBy(() -> RuleSet.accept(List.of(file("a.yaml", "")))).hasMessageContaining("is empty");
            assertThatThrownBy(() -> RuleSet.accept(List.of(file("a.yaml", "x".repeat(RuleSet.MAX_FILE_BYTES + 1)))))
                    .hasMessageContaining("over the");
        }

        @Test
        @DisplayName("refuses more files than the workspace copy can bear")
        void enforcesTheFileCount() {
            List<RuleSet.UploadedFile> many = IntStream.range(0, RuleSet.MAX_FILES + 1)
                    .mapToObj(i -> file(i + ".yaml", "rules: []\n"))
                    .toList();

            assertThatThrownBy(() -> RuleSet.accept(many)).hasMessageContaining("Too many files");
        }
    }

    @Nested
    @DisplayName("reading rule ids without parsing YAML")
    class RuleIds {

        @Test
        @DisplayName("finds ids in the forms rules are actually written in")
        void findsIds() {
            String yaml = """
                    rules:
                      - id: python.lang.security.dangerous-eval
                        message: eval
                      - id: "quoted.rule-id"
                      -   id:   spaced.rule
                    """;

            assertThat(RuleSet.ruleIdsIn(yaml))
                    .containsExactly("python.lang.security.dangerous-eval", "quoted.rule-id", "spaced.rule");
        }

        @Test
        @DisplayName("misses nothing that matters, because it is advisory only")
        void missesAreHarmless() {
            // A rule whose id this does not match is still shipped to Semgrep and still runs;
            // it is only absent from the counts and the impact warning. An exhaustive answer
            // would mean parsing YAML, which this module refuses to do — the accepted parser
            // advisory in document 03 rests on there being no such path.
            assertThat(RuleSet.ruleIdsIn("rules:\n  - id: >\n      folded.id\n")).isEmpty();
        }

        @Test
        @DisplayName("deduplicates across files")
        void deduplicates() {
            List<RuleSet.StoredFile> stored =
                    RuleSet.accept(List.of(file("a.yaml", "- id: shared\n"), file("b.yaml", "- id: shared\n")));

            assertThat(RuleSet.ruleIdsOf(stored)).containsExactly("shared");
        }
    }

    @Nested
    @DisplayName("the content hash an executor caches on")
    class ContentHash {

        @Test
        @DisplayName("ignores the operator's filenames")
        void ignoresUploadedNames() {
            // Re-uploading the same rules under different names must not invalidate every
            // agent's cache.
            String hashA = RuleSet.contentHash(RuleSet.accept(List.of(file("first.yaml", "rules: []\n"))));
            String hashB = RuleSet.contentHash(RuleSet.accept(List.of(file("renamed.yml", "rules: []\n"))));

            assertThat(hashA).isEqualTo(hashB);
        }

        @Test
        @DisplayName("changes when the content or the order changes")
        void followsContentAndOrder() {
            String a = RuleSet.contentHash(RuleSet.accept(List.of(file("a.yaml", "- id: one\n"), file("b.yaml", "- id: two\n"))));
            String b = RuleSet.contentHash(RuleSet.accept(List.of(file("b.yaml", "- id: two\n"), file("a.yaml", "- id: one\n"))));

            assertThat(a).isNotEqualTo(b);
        }
    }

    @Nested
    @DisplayName("what activation would cost")
    class Impact {

        @Test
        @DisplayName("counts the open issues whose rule the new set drops")
        void countsWhatWouldBeLost() {
            // A rule id enters an issue's fingerprint, so a rule that disappears takes its
            // issues with it — with their triage decisions, justifications and review dates. A
            // three-click upload makes that destruction reachable by somebody who does not
            // know it.
            RuleSet.TriageImpact impact = RuleSet.impact(
                    Set.of("kept", "dropped"),
                    Set.of("kept", "added"),
                    Map.of("kept", 3L, "dropped", 7L));

            assertThat(impact.losingIssues()).containsExactly("dropped");
            assertThat(impact.affectedIssues()).isEqualTo(7);
            assertThat(impact.addedRules()).isEqualTo(1);
            assertThat(impact.removedRules()).isEqualTo(1);
        }

        @Test
        @DisplayName("sorts the losing rules, so the warning reads the same twice")
        void sortsTheWarning() {
            RuleSet.TriageImpact impact =
                    RuleSet.impact(Set.of(), Set.of(), Map.of("zulu", 1L, "alpha", 1L, "mike", 1L));

            assertThat(impact.losingIssues()).containsExactly("alpha", "mike", "zulu");
        }

        @Test
        @DisplayName("says nothing is lost when the new set keeps every rule in use")
        void nothingLost() {
            RuleSet.TriageImpact impact = RuleSet.impact(Set.of("a"), Set.of("a", "b"), Map.of("a", 5L));

            assertThat(impact.losingIssues()).isEmpty();
            assertThat(impact.affectedIssues()).isZero();
        }
    }
}
