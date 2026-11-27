package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * {@link ContainerRunner#exportImage} against a stub daemon: what the save asks for, and what is done with an
 * archive of another platform. A daemon older than API 1.48 ignores the {@code platform} of a save, which is what
 * the stub does — it answers whatever archive the test gives it, whatever was asked.
 */
@DisplayName("an image exported for its platform")
class ImageExportTest {

    private static final String REFERENCE = "registry.example:5000/team/app@sha256:" + "ab".repeat(32);
    private static final String CONFIG = "blobs/sha256/" + "c1".repeat(32);

    private HttpServer daemon;
    private final List<String> saves = new ArrayList<>();
    private final List<String> pulls = new ArrayList<>();
    private volatile int saveStatus = 200;
    private volatile byte[] saveAnswer;

    @TempDir
    Path workspace;

    @BeforeEach
    void startDaemon() throws IOException {
        daemon = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        daemon.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getPath().replaceFirst("^/v[0-9.]+", "");
            String query = exchange.getRequestURI().getRawQuery();
            byte[] answer;
            int status;
            if (path.equals("/images/create")) {
                pulls.add(query);
                status = 200;
                answer = "{\"status\":\"Status: Downloaded newer image for app\"}".getBytes(StandardCharsets.UTF_8);
            } else if (path.equals("/images/get")) {
                saves.add(URLDecoder.decode(query, StandardCharsets.UTF_8));
                status = saveStatus;
                answer = saveAnswer;
            } else {
                status = 404;
                answer = "{\"message\":\"not stubbed\"}".getBytes(StandardCharsets.UTF_8);
            }
            exchange.sendResponseHeaders(status, answer.length);
            exchange.getResponseBody().write(answer);
            exchange.close();
        });
        daemon.start();
    }

    @AfterEach
    void stopDaemon() {
        daemon.stop(0);
    }

    private ContainerRunner runner() {
        return new ContainerRunner(
                ContainerRunner.clientAt("tcp://127.0.0.1:" + daemon.getAddress().getPort()),
                ContainerReferenceSetTest.LIMITS);
    }

    private static byte[] archiveOf(String architecture) {
        return new TarBuilder()
                .add(CONFIG, ("{\"architecture\":\"" + architecture + "\",\"os\":\"linux\"}").getBytes(StandardCharsets.UTF_8))
                .add("manifest.json", ("[{\"Config\":\"" + CONFIG + "\",\"RepoTags\":null,\"Layers\":[]}]")
                        .getBytes(StandardCharsets.UTF_8))
                .build();
    }

    @Test
    @DisplayName("the save names the platform the pull named, as an OCI platform")
    void theSaveAsksForThePlatform() throws IOException {
        saveAnswer = archiveOf("amd64");
        Path destination = workspace.resolve("image.tar");

        runner().exportImage(REFERENCE, "linux/amd64", destination);

        assertThat(pulls).singleElement().asString().contains("platform=linux%2Famd64");
        assertThat(saves).containsExactly(
                "names=" + REFERENCE + "&platform={\"os\":\"linux\",\"architecture\":\"amd64\"}");
        assertThat(Files.readAllBytes(destination)).isEqualTo(saveAnswer);
    }

    @Test
    @DisplayName("an archive of another architecture fails the export, and is not left behind")
    void anotherArchitectureIsRefused() {
        saveAnswer = archiveOf("arm64");
        Path destination = workspace.resolve("image.tar");

        assertThatThrownBy(() -> runner().exportImage(REFERENCE, "linux/amd64", destination))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("The Docker daemon exported " + REFERENCE + " as linux/arm64 where linux/amd64 was asked: "
                        + "a daemon selects the platform of a save from API 1.48 on, and another architecture is not "
                        + "scanned in place of the one asked for.");
        assertThat(destination).doesNotExist();
    }

    @Test
    @DisplayName("an archive that cannot be read fails the export rather than passing unchecked")
    void anUnreadableArchiveIsRefused() {
        saveAnswer = "not a tar archive at all".repeat(40).getBytes(StandardCharsets.UTF_8);
        Path destination = workspace.resolve("image.tar");

        assertThatThrownBy(() -> runner().exportImage(REFERENCE, "linux/amd64", destination))
                .hasMessage("The archive exported for " + REFERENCE + " could not be checked for linux/amd64: it is not "
                        + "a tar archive. It is not scanned unchecked.");
        assertThat(destination).doesNotExist();
    }

    @Test
    @DisplayName("without a platform, the daemon chooses at the save as at the pull, and nothing is checked")
    void noPlatformNoCheck() {
        saveAnswer = archiveOf("arm64");
        Path destination = workspace.resolve("image.tar");

        runner().exportImage(REFERENCE, null, destination);

        assertThat(saves).containsExactly("names=" + REFERENCE);
        assertThat(destination).exists();
    }

    @Test
    @DisplayName("a platform that is not os/architecture[/variant] is refused before the daemon is asked anything")
    void aMalformedPlatformIsRefusedFirst() {
        saveAnswer = archiveOf("amd64");

        assertThatThrownBy(() -> runner().exportImage(REFERENCE, "linux/amd64/v1/x", workspace.resolve("image.tar")))
                .hasMessageStartingWith("The image platform \"linux/amd64/v1/x\" is not of the form");
        assertThat(pulls).isEmpty();
        assertThat(saves).isEmpty();
    }

    @Test
    @DisplayName("a save the daemon refuses carries the daemon's own sentence")
    void aRefusedSaveSaysWhy() {
        saveStatus = 404;
        saveAnswer = "{\"message\":\"no suitable export target found\"}".getBytes(StandardCharsets.UTF_8);

        assertThatThrownBy(() -> runner().exportImage(REFERENCE, "linux/amd64", workspace.resolve("image.tar")))
                .hasMessage("could not export " + REFERENCE + ": no suitable export target found");
    }

    @Test
    @DisplayName("the reader bounds what it reads: a manifest larger than its limit is refused")
    void anOversizedEntryIsRefused() {
        byte[] archive = new TarBuilder()
                .add("manifest.json", new byte[ImagePlatform.MANIFEST_LIMIT + 1])
                .build();

        assertThatThrownBy(() -> ImageArchive.entry(new ByteArrayInputStream(archive), "manifest.json", ImagePlatform.MANIFEST_LIMIT))
                .isInstanceOf(ImageArchive.Unreadable.class)
                .hasMessage("manifest.json is larger than 1048576 bytes");
    }

    @Test
    @DisplayName("a base-256 size is read, a negative one is not a size")
    void baseTwoFiftySixSizes() throws Exception {
        byte[] field = new byte[12];
        field[0] = (byte) 0x80;
        field[10] = 0x02;
        field[11] = 0x01;
        assertThat(ImageArchive.number(field, 0, 12)).isEqualTo(513);
        field[0] = (byte) 0xff;
        assertThatThrownBy(() -> ImageArchive.number(field, 0, 12)).isInstanceOf(ImageArchive.Unreadable.class);
        byte[] octal = " 0000755\0".getBytes(StandardCharsets.US_ASCII);
        assertThat(ImageArchive.number(octal, 0, octal.length)).isEqualTo(0755);
        assertThat(ImageArchive.entry(new ByteArrayInputStream(new byte[0]), "x", 1)).isEqualTo(Optional.empty());
    }
}
