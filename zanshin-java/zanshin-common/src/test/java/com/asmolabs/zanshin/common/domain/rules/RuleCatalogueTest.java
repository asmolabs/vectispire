package com.asmolabs.zanshin.common.domain.rules;

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

    private static final List<RuleCatalogue.Entry> ARCHIVE = List.of(
            new RuleCatalogue.Entry("LICENSE", "LGPL-2.1 with Commons Clause"),
            new RuleCatalogue.Entry("python/flask/sqli.yaml", "rules: []"),
            new RuleCatalogue.Entry("python/django/xss.yml", "rules: []"),
            new RuleCatalogue.Entry("java/spring/rce.yaml", "rules: []"),
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
