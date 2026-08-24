package com.asmolabs.vectispire.common.domain.rules;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** What may be fetched, from where, and under what terms. */
@DisplayName("fetching the upstream rule catalogue")
class RuleCatalogueTest {

    /** A minimal rule file, in the shape the selection actually reads: a `rules:` block with an id. */
    private static final String RULE = "rules:\n  - id: a.rule\n    languages: [python]\n";

    private static final List<RuleCatalogue.Entry> ARCHIVE = List.of(
            new RuleCatalogue.Entry("LICENSE", "LGPL-2.1 with Commons Clause"),
            new RuleCatalogue.Entry("python/flask/sqli.yaml", RULE),
            new RuleCatalogue.Entry("python/django/xss.yml", RULE),
            new RuleCatalogue.Entry("java/spring/rce.yaml", RULE),
            new RuleCatalogue.Entry("java/README.md", "not a rule"),
            new RuleCatalogue.Entry(".github/workflows/ci.yaml", "not a rule"));

    @Nested
    @DisplayName("the upstream")
    class Upstream {

        @Test
        @DisplayName("refuses the repository whose licence forbids distributing its rules")
        void theForbiddenUpstreamIsRefused() {
            // Written as a check and not only in decision 0006: a refusal recorded in a document
            // is one somebody works around without knowing there was a reason.
            assertThatThrownBy(() -> RuleCatalogue.requireAllowed("semgrep/semgrep-rules"))
                    .hasMessageContaining("forbid distributing");
        }

        @Test
        @DisplayName("is the fork taken before the relicensing")
        void theAllowedUpstream() {
            assertThat(RuleCatalogue.UPSTREAM).isEqualTo("opengrep/opengrep-rules");
            RuleCatalogue.requireAllowed(RuleCatalogue.UPSTREAM);
        }
    }

    @Nested
    @DisplayName("the pin")
    class Pin {

        @Test
        @DisplayName("is a full commit, because the upstream publishes no tags at all")
        void anythingButAFullCommitIsRefused() {
            // Decision 0006 asked for a pinned tag. `opengrep/opengrep-rules` has none — only
            // `refs/heads/main` — so the requirement was unsatisfiable, and the manual procedure
            // in the README was unsatisfiable for the same reason. A commit pins harder anyway.
            assertThatThrownBy(() -> RuleCatalogue.requireCommit("main")).hasMessageContaining("40-character");
            assertThatThrownBy(() -> RuleCatalogue.requireCommit("v1.0.0")).hasMessageContaining("40-character");
            assertThatThrownBy(() -> RuleCatalogue.requireCommit(null)).hasMessageContaining("40-character");
            // An abbreviation is ambiguous by construction, and a provenance record is the one
            // place that costs.
            assertThatThrownBy(() -> RuleCatalogue.requireCommit("f1d2b56")).hasMessageContaining("40-character");
        }

        @Test
        @DisplayName("accepts a full SHA")
        void aFullShaIsAccepted() {
            RuleCatalogue.requireCommit("f1d2b562b414783763fd02a6ed2736eaed622efa");
        }
    }

    @Nested
    @DisplayName("the files that are not rules")
    class NotRules {

        /**
         * <b>One refused file makes Semgrep exit 7 and analyse nothing at all.</b> Ten fixtures in
         * this upstream reach it as configurations it rejects, and until they were excluded the
         * SAST step produced an empty result on every target, of every scan, reported as
         * "the source analysis did not run".
         */
        @Test
        @DisplayName("a Kubernetes ClusterRole is not a rule file, though it declares `rules:`")
        void aClusterRoleIsNotARuleFile() {
            // The counterexample that defeated a content-only check: `rules:` is also the field
            // where a ClusterRole holds its permissions. The rule id settles it — mandatory in
            // Semgrep's schema, absent from anything that merely borrows the word.
            RuleCatalogue.Entry fixture = new RuleCatalogue.Entry(
                    "yaml/kubernetes/security/legacy-api-clusterrole-excessive-permissions.test.yaml",
                    """
                    apiVersion: rbac.authorization.k8s.io/v1
                    kind: ClusterRole
                    metadata:
                      name: bad-role
                    rules:
                      - apiGroups:
                          - apps
                        resources:
                          - "*"
                        verbs:
                          - "*"
                    """);

            assertThat(selected(fixture)).isEmpty();
        }

        @Test
        @DisplayName("a fixture of the rule-linting rules is excluded by name, because nothing else can")
        void aDeliberatelyMalformedRuleIsExcluded() {
            // These are *deliberately* malformed rule files — that is what a fixture for a rule
            // that lints rules has to be. They carry `rules:` and an id, so no amount of reading
            // separates them from a rule file that is merely wrong. `.test.yaml` is the
            // upstream's own name for them, and here it is the only signal there is.
            RuleCatalogue.Entry fixture = new RuleCatalogue.Entry(
                    "yaml/semgrep/duplicate-id.test.yaml",
                    "rules:\n- id: unchecked-subprocess-call-1\n  patterns:\n  - pattern: subprocess.call(...)\n");

            assertThat(selected(fixture)).isEmpty();
        }

        @Test
        @DisplayName("a rule whose name merely contains \"test\" is kept")
        void aRuleIsNotAFixtureBecauseItSaysTest() {
            // The exclusion is `.test.yaml`, not the word: `python/tests/insecure-test-setup.yaml`
            // is a rule about test code and belongs in the set.
            RuleCatalogue.Entry rule = new RuleCatalogue.Entry("python/tests/insecure-test-setup.yaml", RULE);

            assertThat(selected(rule)).hasSize(1);
        }

        /**
         * What {@code select} returns for this entry alone, its language kept selectable by a
         * genuine rule beside it — otherwise excluding the entry would remove the language too,
         * and the call would fail for the wrong reason.
         */
        private List<RuleSet.UploadedFile> selected(RuleCatalogue.Entry entry) {
            String language = entry.path().substring(0, entry.path().indexOf('/'));

            List<RuleCatalogue.Entry> archive = new java.util.ArrayList<>(ARCHIVE);
            archive.add(new RuleCatalogue.Entry(language + "/genuine/rule.yaml", RULE));
            archive.add(entry);

            return RuleCatalogue.select(RuleCatalogue.describe(archive, "LICENSE"), Set.of(language)).stream()
                    .filter(file -> file.name().equals(entry.path()))
                    .toList();
        }
    }

    @Nested
    @DisplayName("what the archive offers")
    class Contents {

        @Test
        @DisplayName("groups rules by language, and counts only rules")
        void languagesAreCounted() {
            RuleCatalogue.Contents contents = RuleCatalogue.describe(ARCHIVE, "LICENSE");

            // `java/README.md` is not a rule, and `.github` is not a language: a directory
            // offered as one would have somebody select scaffolding and get nothing.
            assertThat(contents.languages()).containsExactly(
                    java.util.Map.entry("java", 1), java.util.Map.entry("python", 2));
        }

        @Test
        @DisplayName("keeps the upstream path, because it becomes the rule id")
        void thePathIsThePayload() {
            List<RuleSet.UploadedFile> files = RuleCatalogue.select(
                    RuleCatalogue.describe(ARCHIVE, "LICENSE"), Set.of("python"));

            // Semgrep derives `check_id` from the path, and the rule id enters an issue's
            // fingerprint. Flattening these names would be invisible today and would resolve
            // every SAST finding the day the upstream moved a file.
            assertThat(files).extracting(RuleSet.UploadedFile::name)
                    .containsExactly("python/django/xss.yml", "python/flask/sqli.yaml");
        }

        @Test
        @DisplayName("refuses an empty selection rather than storing a set with no rules")
        void anEmptySelectionIsRefused() {
            // A rule set containing no rules resolves the whole SAST backlog on activation —
            // the dashboard improves and nothing errors.
            assertThatThrownBy(() -> RuleCatalogue.select(RuleCatalogue.describe(ARCHIVE, "L"), Set.of()))
                    .hasMessageContaining("at least one language");
        }

        @Test
        @DisplayName("refuses a language this tag does not have")
        void unknownLanguagesAreNamed() {
            assertThatThrownBy(() -> RuleCatalogue.select(
                            RuleCatalogue.describe(ARCHIVE, "L"), Set.of("python", "cobol")))
                    .hasMessageContaining("cobol");
        }
    }
}
