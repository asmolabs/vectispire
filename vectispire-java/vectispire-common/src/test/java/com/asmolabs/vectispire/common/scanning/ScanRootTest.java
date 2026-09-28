package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

import com.asmolabs.vectispire.common.domain.scans.FailureKind;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The directory a scan examines, read off the clone — and the scan's permanent failure when the clone
 * does not hold it.
 */
@DisplayName("the directory a scan examines")
class ScanRootTest {

    @TempDir
    Path source;

    @Test
    @DisplayName("a sub-path the clone holds is the scan's root, and no sub-path is the clone's")
    void aPresentSubPathIsTheRoot() throws Exception {
        Files.createDirectories(source.resolve("services/api"));

        assertThat(ScanRunner.scanRoot(source, "services/api", "main")).isEqualTo(source.toRealPath().resolve("services/api"));
        assertThat(ScanRunner.scanRoot(source, "", "main")).isEqualTo(source.toRealPath());
    }

    @Test
    @DisplayName("a sub-path the branch does not hold fails the scan for good, naming both")
    void anAbsentSubPathIsPermanent() {
        CloneFailureException absent =
                catchThrowableOfType(CloneFailureException.class, () -> ScanRunner.scanRoot(source, "services/api", "main"));

        assertThat(absent.kind()).isEqualTo(CloneFailureException.Kind.SUB_PATH);
        assertThat(absent.failureKind()).isEqualTo(FailureKind.PERMANENT);
        assertThat(absent).hasMessageContaining("\"services/api\"").hasMessageContaining("\"main\"");
    }

    @Test
    @DisplayName("a sub-path that is a file is no directory to scan")
    void aFileIsNoRoot() throws Exception {
        Files.writeString(source.resolve("README"), "fixture");

        assertThat(catchThrowableOfType(CloneFailureException.class, () -> ScanRunner.scanRoot(source, "README", "main"))
                        .kind())
                .isEqualTo(CloneFailureException.Kind.SUB_PATH);
    }

    @Test
    @DisplayName("a sub-path leading out of the clone, or refused as text, fails the scan for good")
    void aSubPathOutsideIsPermanent() throws Exception {
        Path outside = Files.createTempDirectory("vectispire-outside-");
        Files.createSymbolicLink(source.resolve("docs"), outside);

        assertThat(catchThrowableOfType(CloneFailureException.class, () -> ScanRunner.scanRoot(source, "docs", "main"))
                        .kind())
                .isEqualTo(CloneFailureException.Kind.SUB_PATH);
        assertThat(catchThrowableOfType(CloneFailureException.class, () -> ScanRunner.normalizedSubPath("../../etc"))
                        .kind())
                .isEqualTo(CloneFailureException.Kind.SUB_PATH);
        assertThat(ScanRunner.normalizedSubPath("services/api/")).isEqualTo("services/api");
    }
}
