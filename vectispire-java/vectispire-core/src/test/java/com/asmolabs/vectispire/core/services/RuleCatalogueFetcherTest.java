package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.rules.RuleCatalogue;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * What the rule fetch keeps from the checkout it clones, pinned on a local tree.
 *
 * <p>The clone itself needs the network and a fixed upstream, so it stays out of the unit suite;
 * what is decided locally — which files are read, where the licence must be, and that its absence
 * is a refusal — had no test at all.
 */
@DisplayName("reading a fetched rule catalogue")
class RuleCatalogueFetcherTest {

    @Test
    @DisplayName("keeps the rule files and the licence, and nothing from .git, tests or docs")
    void readsOnlyWhatMatters(@TempDir Path checkout) throws Exception {
        write(checkout, "LICENSE", "Semgrep Rules License v1.0");
        write(checkout, "python/lang/eval.yaml", "rules: []");
        write(checkout, "java/spring/csrf.yml", "rules: []");
        write(checkout, "README.md", "docs");
        write(checkout, "python/lang/eval.py", "eval(x)");
        write(checkout, ".git/config", "[core]");
        write(checkout, ".git/hooks/pre.yaml", "not a rule");

        List<String> paths = RuleCatalogueFetcher.read(checkout).stream().map(RuleCatalogue.Entry::path).toList();

        assertThat(paths).containsExactlyInAnyOrder("LICENSE", "python/lang/eval.yaml", "java/spring/csrf.yml");
    }

    @Test
    @DisplayName("takes the licence at the root, not one belonging to a sub-folder")
    void theLicenceIsTheRootOne(@TempDir Path checkout) throws Exception {
        write(checkout, "vendored/LICENSE", "somebody else's terms");
        write(checkout, "LICENSE.md", "the catalogue's terms");

        assertThat(RuleCatalogueFetcher.licenceOf(RuleCatalogueFetcher.read(checkout))).isEqualTo("the catalogue's terms");
    }

    @Test
    @DisplayName("refuses a catalogue with no licence at its root rather than offering rules nobody agreed to")
    void noLicenceIsARefusal(@TempDir Path checkout) throws Exception {
        write(checkout, "python/lang/eval.yaml", "rules: []");
        write(checkout, "vendored/LICENSE", "not the catalogue's");

        assertThatThrownBy(() -> RuleCatalogueFetcher.licenceOf(RuleCatalogueFetcher.read(checkout)))
                .isInstanceOf(RuleCatalogueFetcher.FetchFailureException.class)
                .hasMessageContaining("No LICENSE file at the root");
    }

    private static void write(Path root, String relative, String content) throws Exception {
        Path file = root.resolve(relative);
        Files.createDirectories(file.getParent());
        Files.writeString(file, content);
    }
}
