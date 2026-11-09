package com.asmolabs.vectispire.common.domain.sarif;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The path a plugin or imported issue is fingerprinted on. Every expectation here is a data
 * contract: changing one resolves and recreates the issues it covers.
 */
@DisplayName("a SARIF location as a fingerprinted path")
class SarifPathsTest {

    private static final List<String> PLUGIN = List.of("/repo/source");

    @Test
    @DisplayName("relative locations keep their segments, with empty and dot segments dropped")
    void relative() {
        assertThat(SarifPaths.normalize("src/main/App.java", List.of())).isEqualTo("src/main/App.java");
        assertThat(SarifPaths.normalize("./src//main/./App.java", List.of())).isEqualTo("src/main/App.java");
        assertThat(SarifPaths.normalize("src\\main\\App.java", List.of())).isEqualTo("src/main/App.java");
    }

    @Test
    @DisplayName("escapes are decoded as UTF-8, and a plus stays a plus")
    void decoded() {
        assertThat(SarifPaths.normalize("src/My%20File%C3%A9.java", List.of())).isEqualTo("src/My Fileé.java");
        assertThat(SarifPaths.normalize("src/a+b.c", List.of())).isEqualTo("src/a+b.c");
    }

    @Test
    @DisplayName("a plugin's absolute paths under its mount become relative, however they are spelled")
    void underTheMount() {
        assertThat(SarifPaths.normalize("/repo/source/src/App.java", PLUGIN)).isEqualTo("src/App.java");
        assertThat(SarifPaths.normalize("file:///repo/source/src/App.java", PLUGIN)).isEqualTo("src/App.java");
        assertThat(SarifPaths.normalize("file://localhost/repo/source/src/App.java", PLUGIN)).isEqualTo("src/App.java");
        assertThat(SarifPaths.normalize("/repo/source", PLUGIN)).isNull();
    }

    @Test
    @DisplayName("a location naming no file is null, not an empty string that would compare differently")
    void noFile() {
        assertThat(SarifPaths.normalize(null, PLUGIN)).isNull();
        assertThat(SarifPaths.normalize("  ", PLUGIN)).isNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "https://example.com/App.java",
        "http://intranet/src/App.java",
        "file://attacker/share/App.java",
        // Under the mount by its path, on another machine by its host: not the tree Vectispire saw.
        "file://attacker/repo/source/App.java",
        // A scheme with no authority reads like a relative path once the scheme is dropped.
        "jar:src/App.java",
        "vscode:src/App.java",
        "file:///etc/passwd",
        "/etc/passwd",
        "/repo/sourcery/App.java",
        "C:/work/App.java",
        "../outside/App.java",
        "src/%2E%2E/%2E%2E/etc/passwd",
        "src/%00App.java",
        "src/%E9.java",
        "src/%4",
    })
    @DisplayName("a location outside the analysed tree, or one that cannot be read, is refused")
    void refused(String uri) {
        assertThatThrownBy(() -> SarifPaths.normalize(uri, PLUGIN)).isInstanceOf(InvalidSarifException.class);
    }

    @Test
    @DisplayName("an import knows no root: any absolute path is outside the tree")
    void importsKnowNoRoot() {
        assertThatThrownBy(() -> SarifPaths.normalize("/builds/group/project/src/App.java", List.of()))
                .isInstanceOf(InvalidSarifException.class)
                .hasMessageContaining("relative");
    }
}
