package com.asmolabs.zanshin.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The rules Zanshin ships are actually in the jar.
 *
 * <p><b>They were not, and every repository scan failed because of it</b> — "could not place
 * rules from rules", from a {@code Path.of("rules")} resolved against whatever directory the
 * process started in. Nothing in the tree, the jar or the image ever held such a directory.
 *
 * <p>It survived the whole port because no test needed the real files: the unit suites build a
 * {@code RulePlacement} over a temporary directory, and container scans run the dependency step
 * alone and never place a rule. Only a repository scan, run for real, reaches this code.
 */
@DisplayName("the rules Zanshin ships")
class BundledRulesTest {

    @Test
    @DisplayName("are packaged, and land as files a sibling container can read")
    void theyAreInTheJar(@TempDir Path into) {
        Path root = BundledRules.materialise(into);

        for (String file : BundledRules.expected()) {
            assertThat(root.resolve(file))
                    .describedAs("%s must ship in the jar", file)
                    .isRegularFile()
                    .isNotEmptyFile();
        }
    }

    @Test
    @DisplayName("include the gitleaks configuration, which is a security property and not a default")
    void theGitleaksConfigurationIsThere(@TempDir Path into) throws Exception {
        String configuration = Files.readString(BundledRules.materialise(into).resolve("gitleaks/gitleaks.toml"));

        // Without `--config` pointing at this file, gitleaks reads `.gitleaks.toml` from the
        // repository being scanned — written by whoever is being audited. An empty file with a
        // universal allowlist switches detection off with no error, and the scan then reports
        // "analysed, found nothing", silently resolving that target's whole secrets history.
        assertThat(configuration).contains("useDefault = true");

        // No allowlist, deliberately: it would be the first thing an attacker widened. Checked
        // on declarations rather than on the text — the file explains at length why the section
        // is absent, and a naive search finds the explanation instead of a section.
        assertThat(configuration.lines().map(String::strip).filter(line -> !line.startsWith("#")))
                .noneMatch(line -> line.startsWith("[allowlist]"));
    }

    @Test
    @DisplayName("carry a rule id in the fingerprint's spelling, which must not drift")
    void theRuleIdIsPinned(@TempDir Path into) throws Exception {
        String rule = Files.readString(
                BundledRules.materialise(into).resolve("semgrep/python/dangerous-eval.yaml"));

        // A rule id enters an issue's fingerprint. Changing this string resolves every finding
        // the rule produced and recreates them as new, losing the triage attached to them —
        // silently, across every target. Pinned here so that a rename is a failing test rather
        // than a discovery six months later.
        assertThat(rule).contains("id: zanshin.python.eval-on-input");
    }
}
