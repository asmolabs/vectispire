package com.asmolabs.zanshin.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.zanshin.common.domain.rules.RuleSet;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@DisplayName("rule placement")
class RulePlacementTest {

    @TempDir
    Path scratch;

    private RulePlacement placement;
    private Path bundled;

    @BeforeEach
    void bundledTree() throws IOException {
        bundled = scratch.resolve("bundled");
        Files.createDirectories(bundled.resolve("semgrep/python"));
        Files.createDirectories(bundled.resolve("gitleaks"));
        Files.writeString(bundled.resolve("semgrep/python/dangerous-eval.yaml"), "rules: []\n");
        Files.writeString(bundled.resolve("gitleaks/gitleaks.toml"), "[extend]\n");
        placement = new RulePlacement(bundled);
    }

    private Workspace workspace() throws IOException {
        Path root = Files.createTempDirectory(scratch, "ws-");
        return new Workspace(root, root.resolve(Workspace.SOURCE_SUBDIR), root.resolve(Workspace.RULES_SUBDIR));
    }

    @Test
    @DisplayName("places both trees, because the secrets config is needed even with SAST off")
    void placesBothTrees() throws IOException {
        // Otherwise the tool falls back to the scanned repository's own configuration — the
        // target supplying the rules of its own audit.
        Workspace workspace = workspace();

        placement.placeBundled(workspace);

        assertThat(workspace.rules().resolve("gitleaks/gitleaks.toml")).exists();
        assertThat(workspace.rules().resolve("semgrep/python/dangerous-eval.yaml")).exists();
    }

    @Nested
    @DisplayName("the operator's own directory")
    class OperatorDirectory {

        @Test
        @DisplayName("does nothing when none is configured")
        void silentWithoutOne() throws IOException {
            Workspace workspace = workspace();
            placement.placeBundled(workspace);

            assertThat(placement.placeOperatorRules(workspace, null)).isFalse();
            assertThat(placement.placeOperatorRules(workspace, "   ")).isFalse();
            assertThat(workspace.rules().resolve("semgrep/operator")).doesNotExist();
        }

        @Test
        @DisplayName("lands beside the bundled rules, never among them")
        void landsInASubdirectory() throws IOException {
            // Keeping them apart means an operator file can never silently overwrite a bundled
            // one by sharing its name.
            Workspace workspace = workspace();
            placement.placeBundled(workspace);
            Path operator = Files.createDirectories(scratch.resolve("operator-rules"));
            Files.writeString(operator.resolve("extra.yaml"), "rules: []\n");

            assertThat(placement.placeOperatorRules(workspace, operator.toString())).isTrue();

            assertThat(workspace.rules().resolve("semgrep/operator/extra.yaml")).exists();
            assertThat(workspace.rules().resolve("semgrep/python/dangerous-eval.yaml")).exists();
        }

        @Test
        @DisplayName("throws rather than scanning with the bundled rules alone")
        void refusesToDegrade() throws IOException {
            // The dangerous outcome is not the exception, it is the clean run: the analyser
            // would exit 0 with a shorter list, which reads as "analysed, those issues are
            // gone" and resolves everything the operator's rules had found.
            Workspace workspace = workspace();
            placement.placeBundled(workspace);

            assertThatThrownBy(() -> placement.placeOperatorRules(workspace, scratch.resolve("absent").toString()))
                    .isInstanceOf(OperatorRulesUnavailableException.class)
                    // The message names the variable, so the misconfiguration is findable. A
                    // bare "cannot read" sends the operator to the repository instead.
                    .hasMessageContaining("ZANSHIN_SEMGREP_RULES_DIR");
        }

        @Test
        @DisplayName("throws when the path is a file rather than a directory")
        void refusesAFile() throws IOException {
            Workspace workspace = workspace();
            Path file = Files.writeString(scratch.resolve("rules.yaml"), "rules: []\n");

            assertThatThrownBy(() -> placement.placeOperatorRules(workspace, file.toString()))
                    .hasMessageContaining("not a directory");
        }
    }

    @Nested
    @DisplayName("an uploaded rule set")
    class UploadedSet {

        private final RulePlacement.RuleSetProvider oneFile =
                hash -> List.of(new RuleSet.StoredFile("rule-0001.yaml", "operator.yaml", "rules: []\n"));

        @Test
        @DisplayName("replaces the environment directory rather than merging with it")
        void precedenceIsExclusive() throws IOException {
            // Merging looks friendlier and reintroduces the defect the upload exists to remove:
            // the directory is per-executor, so a merged result differs between an agent that
            // has it and one that does not, and the backlog resolves and reappears as the two
            // take turns.
            Workspace workspace = workspace();
            placement.placeBundled(workspace);
            Path fromEnvironment = Files.createDirectories(scratch.resolve("env-rules"));
            Files.writeString(fromEnvironment.resolve("from-env.yaml"), "rules: []\n");

            assertThat(placement.placeRuleSet(workspace, "abc123", oneFile, fromEnvironment.toString())).isTrue();

            assertThat(workspace.rules().resolve("semgrep/operator")).isDirectoryContaining("glob:**/rule-0001.yaml");
            assertThat(workspace.rules().resolve("semgrep/operator/from-env.yaml")).doesNotExist();
        }

        @Test
        @DisplayName("falls back to the environment directory when no set is named")
        void fallsBackToTheDirectory() throws IOException {
            Workspace workspace = workspace();
            placement.placeBundled(workspace);
            Path fromEnvironment = Files.createDirectories(scratch.resolve("env-rules-2"));
            Files.writeString(fromEnvironment.resolve("from-env.yaml"), "rules: []\n");

            assertThat(placement.placeRuleSet(workspace, null, null, null)).isFalse();
            assertThat(placement.placeRuleSet(workspace, null, null, fromEnvironment.toString())).isTrue();
            assertThat(workspace.rules().resolve("semgrep/operator/from-env.yaml")).exists();
        }

        @Test
        @DisplayName("throws when the executor cannot obtain the named set")
        void refusesWithoutAProvider() throws IOException {
            Workspace workspace = workspace();
            placement.placeBundled(workspace);

            assertThatThrownBy(() -> placement.placeRuleSet(workspace, "abc123", null, null))
                    .isInstanceOf(OperatorRulesUnavailableException.class)
                    .hasMessageContaining("no way to fetch it");
        }

        @Test
        @DisplayName("throws on an empty set rather than scanning with the bundled rules")
        void refusesAnEmptySet() throws IOException {
            Workspace workspace = workspace();
            placement.placeBundled(workspace);

            assertThatThrownBy(() -> placement.placeRuleSet(workspace, "abc123", hash -> List.of(), null))
                    .hasMessageContaining("came back empty");
        }

        @Test
        @DisplayName("throws when the fetch itself fails")
        void refusesOnFetchFailure() throws IOException {
            Workspace workspace = workspace();
            placement.placeBundled(workspace);

            assertThatThrownBy(() -> placement.placeRuleSet(workspace, "abc123", hash -> {
                        throw new IllegalStateException("HTTP 404");
                    }, null))
                    .hasMessageContaining("could not be fetched");
        }

        @Test
        @DisplayName("writes under the basename, whatever path the provider returns")
        void usesTheBasenameOnly() throws IOException {
            // Zanshin generates these paths, but the content arrives over HTTP on an agent. A
            // guard costing one call is worth more than the argument that it cannot be hostile.
            Workspace workspace = workspace();
            placement.placeBundled(workspace);

            placement.placeRuleSet(workspace, "abc123",
                    hash -> List.of(new RuleSet.StoredFile("../../escaped.yaml", "x.yaml", "rules: []\n")), null);

            assertThat(workspace.rules().resolve("semgrep/operator/escaped.yaml")).exists();
            assertThat(workspace.root().resolve("escaped.yaml")).doesNotExist();
        }
    }
}
