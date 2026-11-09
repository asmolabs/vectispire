package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.plugins.Language;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@DisplayName("the language census of a checked-out tree")
class LanguageCensusTest {

    @TempDir
    Path tree;

    private void file(String relative) throws IOException {
        Path path = tree.resolve(relative);
        Files.createDirectories(path.getParent());
        Files.writeString(path, "x");
    }

    @Test
    @DisplayName("counts the languages its sources and manifests name")
    void counts() throws IOException {
        file("pom.xml");
        file("src/main/java/Main.java");
        file("scripts/deploy.sh");
        file("README.md");

        LanguageCensus.Census census = LanguageCensus.of(tree, Set.of());

        assertThat(census.complete()).isTrue();
        assertThat(census.found()).containsExactlyInAnyOrder(Language.JAVA, Language.BASH);
        assertThat(census.applies(Set.of(Language.JAVA, Language.GO))).isTrue();
        assertThat(census.applies(Set.of(Language.PYTHON)))
                .as("a complete census without the plugin's language proves it does not apply")
                .isFalse();
    }

    @Test
    @DisplayName("a link is neither followed nor counted: the tree cannot make the census walk the host")
    void linksAreNotFollowed(@TempDir Path outside) throws IOException {
        Files.writeString(outside.resolve("lib.rs"), "x");
        Files.createSymbolicLink(tree.resolve("elsewhere"), outside);
        Files.createSymbolicLink(tree.resolve("fake.py"), outside.resolve("lib.rs"));

        LanguageCensus.Census census = LanguageCensus.of(tree, Set.of());

        assertThat(census.found()).doesNotContain(Language.RUST, Language.PYTHON);
        assertThat(census.complete()).isTrue();
    }

    @Test
    @DisplayName("the clone's metadata and installed dependencies are not the code")
    void skipsMetadataAndDependencies() throws IOException {
        file(".git/hooks/pre-commit.sh");
        file("node_modules/left-pad/index.js");

        LanguageCensus.Census census = LanguageCensus.of(tree, Set.of());

        assertThat(census.found()).isEmpty();
        assertThat(census.complete()).isTrue();
    }

    @Test
    @DisplayName("a walk stopped by its bound says so, and then every plugin applies")
    void anExhaustedWalkProvesNothing() throws IOException {
        for (int i = 0; i < 50; i++) {
            file("docs/page-" + i + ".txt");
        }
        file("zz/last.py");

        LanguageCensus.Census census = LanguageCensus.of(tree, Set.of(), 10, Duration.ofMinutes(1), System::nanoTime);

        assertThat(census.complete()).isFalse();
        assertThat(census.applies(Set.of(Language.PYTHON)))
                .as("an incomplete census cannot prove a language absent — \"not applicable\" is a claim")
                .isTrue();
    }

    @Test
    @DisplayName("a walk past its deadline stops, and says so")
    void theDeadlineStopsIt() throws IOException {
        for (int i = 0; i < 20; i++) {
            file("src/f" + i + ".txt");
        }
        AtomicLong clock = new AtomicLong();
        // Every reading of the clock is a minute later: the second entry is already past it.
        LanguageCensus.Census census = LanguageCensus.of(
                tree, Set.of(), 1_000, Duration.ofSeconds(30), () -> clock.addAndGet(Duration.ofMinutes(1).toNanos()));

        assertThat(census.complete()).isFalse();
    }

    @Test
    @DisplayName("the walk ends as soon as every language asked about has been seen, and that answer is whole")
    void stopsEarly() throws IOException {
        file("a/pom.xml");
        for (int i = 0; i < 100; i++) {
            file("b/page-" + i + ".txt");
        }

        LanguageCensus.Census census = LanguageCensus.of(tree, Set.of(Language.JAVA), 5_000, Duration.ofMinutes(1),
                System::nanoTime);

        assertThat(census.complete()).isTrue();
        assertThat(census.applies(Set.of(Language.JAVA))).isTrue();
    }

    @Test
    @DisplayName("no tree is not \"no language\": the census cannot make a plugin not applicable by failing")
    void noTree() {
        LanguageCensus.Census census = LanguageCensus.of(tree.resolve("absent"), Set.of());

        assertThat(census.complete()).isFalse();
        assertThat(census.applies(Set.of(Language.GO))).isTrue();
    }

    @Test
    @DisplayName("ten thousand files with names built to hurt a matcher are counted in linear time")
    void adversarialNames() throws IOException {
        String stem = ".a".repeat(60);
        for (int i = 0; i < 10_000; i++) {
            file("d" + (i % 20) + "/" + i + stem + ".notalanguage");
        }
        file("d0/real.go");

        Assertions.assertTimeoutPreemptively(Duration.ofSeconds(20), () -> {
            LanguageCensus.Census census = LanguageCensus.of(tree, Set.of());
            assertThat(census.complete()).isTrue();
            assertThat(census.found()).containsExactly(Language.GO);
        });
    }
}
