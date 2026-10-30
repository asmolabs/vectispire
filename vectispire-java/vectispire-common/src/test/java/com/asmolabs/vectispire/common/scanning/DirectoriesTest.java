package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

@DisplayName("the directories a scan leaves behind")
class DirectoriesTest {

    @Test
    @DisplayName("a tree goes, its deepest files first")
    void deletesTheWholeTree(@TempDir Path parent) throws IOException {
        Path root = parent.resolve("workspace");
        Files.createDirectories(root.resolve("source/src/main"));
        Files.writeString(root.resolve("source/src/main/App.java"), "class App {}");
        Files.writeString(root.resolve("secrets.json"), "[]");

        Directories.deleteRecursively(root);

        assertThat(root).doesNotExist();
    }

    @Test
    @DisplayName("an absent directory is not an error")
    void anAbsentDirectoryIsNotAnError(@TempDir Path parent) {
        // Every caller deletes in a `finally` or after a failure: throwing here would replace the
        // exception that explains the failure.
        assertThatCode(() -> Directories.deleteRecursively(parent.resolve("never-created")))
                .doesNotThrowAnyException();
    }
}
