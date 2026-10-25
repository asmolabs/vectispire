package com.asmolabs.vectispire.agent.kubernetes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class MountArchivesTest {

    @TempDir
    Path directory;

    @Test
    void aTreeGoesInWhole_datedSoThatWhatTheScannerWritesStandsOut() throws IOException {
        Path tree = Files.createDirectories(directory.resolve("tree/source/a"));
        Files.writeString(tree.resolve("file.txt"), "content");
        Files.createSymbolicLink(tree.resolve("link"), Path.of("file.txt"));
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        MountArchives.write(directory.resolve("tree"), bytes);

        List<String> names = new ArrayList<>();
        try (TarArchiveInputStream tar = new TarArchiveInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
            for (TarArchiveEntry entry; (entry = tar.getNextEntry()) != null; ) {
                names.add(entry.getName() + (entry.isSymbolicLink() ? " -> " + entry.getLinkName() : ""));
                assertThat(entry.getModTime().getTime()).as(entry.getName()).isZero();
            }
        }
        assertThat(names).containsExactlyInAnyOrder("source/", "source/a/", "source/a/file.txt",
                "source/a/link -> file.txt");
    }

    @Test
    void aFileGoesInUnderItsOwnName() throws IOException {
        Path key = Files.writeString(directory.resolve("key.pub"), "k");
        assertThat(MountArchives.nameOf(key)).isEqualTo("key.pub");
        assertThat(MountArchives.nameOf(directory)).isEmpty();
    }

    @Test
    void writtenFilesComeBackIntoTheMount() throws IOException {
        Path mount = Files.createDirectories(directory.resolve("mount"));
        Files.writeString(mount.resolve("kept.txt"), "kept");
        MountArchives.extractWritten(archive("./report.json", "[]", "./deep/er.txt", "x"), mount);

        assertThat(Files.readString(mount.resolve("report.json"))).isEqualTo("[]");
        assertThat(Files.readString(mount.resolve("deep/er.txt"))).isEqualTo("x");
        assertThat(Files.readString(mount.resolve("kept.txt"))).isEqualTo("kept");
    }

    @Test
    void aNameOutsideTheMountIsRefused() throws IOException {
        Path mount = Files.createDirectories(directory.resolve("mount"));
        assertThatThrownBy(() -> MountArchives.extractWritten(archive("../escaped", "x"), mount))
                .hasMessageContaining("outside its mount");
        assertThatThrownBy(() -> MountArchives.extractWritten(archive("/etc/escaped", "x"), mount))
                .hasMessageContaining("outside its mount");
        assertThat(directory.resolve("escaped")).doesNotExist();
    }

    @Test
    void aWriteThroughALinkInTheWorkspaceIsRefused() throws IOException {
        Path mount = Files.createDirectories(directory.resolve("mount"));
        Path elsewhere = Files.createDirectories(directory.resolve("elsewhere"));
        Files.createSymbolicLink(mount.resolve("door"), elsewhere);
        assertThatThrownBy(() -> MountArchives.extractWritten(archive("door/planted", "x"), mount))
                .hasMessageContaining("through the link");
        Files.createSymbolicLink(mount.resolve("target"), elsewhere.resolve("file"));
        assertThatThrownBy(() -> MountArchives.extractWritten(archive("target", "x"), mount))
                .hasMessageContaining("over a link");
        assertThat(elsewhere).isEmptyDirectory();
    }

    @Test
    void aLinkTheScannerWroteIsNotBroughtBack() throws IOException {
        Path mount = Files.createDirectories(directory.resolve("mount"));
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (TarArchiveOutputStream tar = new TarArchiveOutputStream(bytes)) {
            TarArchiveEntry link = new TarArchiveEntry("report.json", TarArchiveEntry.LF_SYMLINK);
            link.setLinkName("/etc/passwd");
            tar.putArchiveEntry(link);
            tar.closeArchiveEntry();
        }
        assertThatThrownBy(() -> MountArchives.extractWritten(new ByteArrayInputStream(bytes.toByteArray()), mount))
                .hasMessageContaining("not a regular file");
        assertThat(mount).isEmptyDirectory();
    }

    private static ByteArrayInputStream archive(String... namesAndContents) throws IOException {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (TarArchiveOutputStream tar = new TarArchiveOutputStream(bytes)) {
            for (int i = 0; i < namesAndContents.length; i += 2) {
                byte[] content = namesAndContents[i + 1].getBytes(StandardCharsets.UTF_8);
                TarArchiveEntry entry = new TarArchiveEntry(namesAndContents[i], true);
                entry.setSize(content.length);
                tar.putArchiveEntry(entry);
                tar.write(content);
                tar.closeArchiveEntry();
            }
        }
        return new ByteArrayInputStream(bytes.toByteArray());
    }
}
