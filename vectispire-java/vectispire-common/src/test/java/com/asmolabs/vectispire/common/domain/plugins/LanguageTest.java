package com.asmolabs.vectispire.common.domain.plugins;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.Set;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("the languages a plugin may declare")
class LanguageTest {

    @Test
    @DisplayName("a file is recognised by its extension, whatever its case")
    void byExtension() {
        assertThat(Language.ofFileName("Main.java")).containsExactly(Language.JAVA);
        assertThat(Language.ofFileName("APP.PY")).containsExactly(Language.PYTHON);
        assertThat(Language.ofFileName("index.tsx")).containsExactly(Language.TYPESCRIPT);
        assertThat(Language.ofFileName("main.tf")).containsExactly(Language.TERRAFORM);
    }

    @Test
    @DisplayName("a manifest names its language before any source file is seen")
    void byManifest() {
        assertThat(Language.ofFileName("pom.xml")).containsExactly(Language.JAVA);
        assertThat(Language.ofFileName("pyproject.toml")).containsExactly(Language.PYTHON);
        assertThat(Language.ofFileName("go.mod")).containsExactly(Language.GO);
        assertThat(Language.ofFileName("Cargo.toml")).containsExactly(Language.RUST);
        assertThat(Language.ofFileName("Dockerfile")).containsExactly(Language.DOCKERFILE);
        assertThat(Language.ofFileName("Dockerfile.prod")).containsExactly(Language.DOCKERFILE);
    }

    @Test
    @DisplayName("a Gradle Kotlin script names the build's language and its own")
    void severalAtOnce() {
        assertThat(Language.ofFileName("build.gradle.kts")).containsExactlyInAnyOrder(Language.JAVA, Language.KOTLIN);
    }

    @Test
    @DisplayName("a name that says nothing answers nothing — no extension, a trailing dot, a dotfile")
    void nothing() {
        assertThat(Language.ofFileName("LICENSE")).isEmpty();
        assertThat(Language.ofFileName("notes.")).isEmpty();
        assertThat(Language.ofFileName(".gitignore")).isEmpty();
        assertThat(Language.ofFileName("")).isEmpty();
        assertThat(Language.ofFileName(null)).isEmpty();
    }

    @Test
    @DisplayName("the wire names are the catalogue's directories, parsed leniently on case and refused when unknown")
    void wireNames() {
        assertThat(Language.fromWireName(" Java ")).contains(Language.JAVA);
        assertThat(Language.fromWireName("generic")).isEmpty();
        assertThatThrownBy(() -> Language.fromJson("cobol"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cobol")
                .hasMessageContaining("java");
        assertThat(Set.copyOf(Language.wireNames())).hasSize(Language.values().length);
    }

    @Test
    @DisplayName("recognition is linear in the name: five million characters built to backtrack answer at once")
    void linearTime() {
        // The shapes that hurt a backtracking matcher: long runs of the separator and of a letter,
        // alternating, ending on something that is not an extension. A pattern such as
        // `(.*\.)*(\w+)$` is exponential here; `lastIndexOf` and a map lookup are not.
        String adversarial = ".a".repeat(1_250_000) + "a".repeat(2_500_000) + "!";

        Assertions.assertTimeoutPreemptively(Duration.ofSeconds(2), () ->
                assertThat(Language.ofFileName(adversarial)).isEmpty());
    }
}
