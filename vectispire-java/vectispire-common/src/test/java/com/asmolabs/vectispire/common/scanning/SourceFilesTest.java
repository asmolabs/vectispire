package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Reading the analysed repository from inside the JVM: never through a link, never without a bound,
 * never outside the clone.
 */
@DisplayName("reading files of the analysed repository")
class SourceFilesTest {

    @TempDir
    Path temp;

    @Test
    @DisplayName("a file reached through a symbolic link is not read")
    void aLinkIsNotFollowed() throws IOException {
        // `package.json -> /etc/…` read a host file into the recorded version; `a.js -> /dev/zero`
        // never reached end of file.
        Path outside = Files.writeString(temp.resolve("host-secret.txt"), "not the repository's");
        Path link = Files.createSymbolicLink(temp.resolve("link.js"), outside);

        assertThat(SourceFiles.readText(link)).isEmpty();
        assertThat(SourceFiles.isRegularFile(link)).isFalse();
        assertThat(SourceFiles.readText(outside)).contains("not the repository's");
    }

    @Test
    @DisplayName("a file larger than the bound is not read")
    void anOversizedFileIsNotRead() throws IOException {
        Path big = temp.resolve("big.js");
        Files.write(big, new byte[(int) SourceFiles.MAX_BYTES + 1]);

        assertThat(SourceFiles.readText(big)).isEmpty();
    }

    @Test
    @DisplayName("a sub-path that is a link out of the clone is refused")
    void aSubPathLinkingOutIsRefused() throws IOException {
        Path clone = Files.createDirectory(temp.resolve("clone"));
        Path elsewhere = Files.createDirectory(temp.resolve("another-teams-clone"));
        Files.createSymbolicLink(clone.resolve("docs"), elsewhere);
        Files.createDirectories(clone.resolve("services/api"));

        assertThatThrownBy(() -> SourceFiles.within(clone, "docs"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("outside the repository");
        assertThatThrownBy(() -> SourceFiles.within(clone, "../another-teams-clone"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(SourceFiles.within(clone, "services/api")).isEqualTo(clone.toRealPath().resolve("services/api"));
        assertThat(SourceFiles.within(clone, "")).isEqualTo(clone.toRealPath());
    }
}
