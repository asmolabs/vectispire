package com.asmolabs.vectispire.common.scanning;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.checklists.Sheet;
import com.asmolabs.vectispire.common.domain.checklists.Workbook;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportMediaType;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportOutputCheck;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportPluginManifest;
import com.asmolabs.vectispire.common.scanning.scanners.PluginScanner;
import com.asmolabs.vectispire.common.scanning.scanners.ReportPluginRenderer;
import com.asmolabs.vectispire.reportdemo.ReportDemo;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The demonstration plugin's image, run end to end in the closed shape a report plugin runs in (decision 0035
 * §6, the second half of its contract test): built by Jib before this suite ({@code
 * :vectispire-report-demo:jibDockerBuild}), called with its published manifest's arguments, limits and output
 * name, through the real {@link ContainerRunner} — no network, a read-only root, a {@code noexec} scratch, the
 * export alone and read-only, an output of sixteen inodes bounded by {@code max_output_bytes}, never root.
 *
 * <p><b>The shape {@link ReportPluginRenderer} builds, without its signer check.</b> The renderer verifies the
 * image's signature with cosign before the pull, and an image built here has neither a registry nor a
 * signature — {@link ReportPluginRendererIntegrationTest} says why this suite builds neither, and runs the
 * verifier against a signed public image instead. So this test assembles the same {@link ContainerRun} the
 * renderer does after the verification, from the same constants; what it proves is that the image honours the
 * contract inside that shape. The signature of the published image is the release's to make and verify
 * ({@code release.yml}), and only a tag exercises it.
 *
 * <p>Needs a Docker daemon and the image's base pulled once. <b>No skip guard.</b>
 */
@DisplayName("the demonstration plugin's image, in the closed shape of a report plugin")
class ReportDemoImageIntegrationTest {

    private static final ObjectMapper JSON = new ObjectMapper();
    private static final ContainerRunner RUNNER = new ContainerRunner();

    /** The image Jib built, by the tag the task gave it; the property says which. */
    private static final String IMAGE = System.getProperty("vectispire.reportDemo.image", "vectispire-report-demo:latest");

    private static final Path PROJECT = Path.of(System.getProperty("vectispire.reportDemo.dir",
            "../vectispire-report-demo"));

    private static ReportPluginManifest manifest;

    @BeforeAll
    static void daemonAndManifest() throws IOException {
        assertThat(RUNNER.isAvailable())
                .as("this suite needs a Docker daemon; it does not skip itself when there is none")
                .isTrue();
        // The manifest the release publishes, filled as the release fills it: what runs here is what an
        // installation that pasted it would run, but for the image reference.
        String filled = Files.readString(PROJECT.resolve("manifest.template.json"))
                .replace("{{image}}", "ghcr.io/asmolabs/vectispire-report-demo@sha256:" + "0".repeat(64))
                .replace("{{identity}}",
                        "https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/v0.0.0");
        manifest = JSON.readValue(filled, ReportPluginManifest.class).validated();
        assertThat(manifest.mediaType()).isEqualTo(ReportMediaType.XLSX);
    }

    @Test
    @DisplayName("produced: exit 0, a workbook the platform's reader accepts, the in-process one cell for cell, the same bytes twice")
    void produced() {
        byte[] export = sample();

        Run first = run(export);
        Run second = run(export);

        assertThat(first.exitCode()).as(first.stderr()).isZero();
        assertThat(first.output()).as("its file, read back as a regular file").isNotNull();
        assertThat(second.output()).as("deterministic in its image").isEqualTo(first.output());

        assertThat(ReportOutputCheck.check(manifest.mediaType(), first.output(), manifest.maxOutputBytes()))
                .as("the check the platform runs before it signs the file")
                .isEqualTo(new ReportOutputCheck.Verdict.Accepted());
        Workbook inImage = Workbook.read(first.output(), manifest.maxOutputBytes());
        Workbook inProcess = Workbook.read(ReportDemo.render(export), manifest.maxOutputBytes());
        assertThat(inImage.sheets()).extracting(Sheet::name).containsExactly("Summary", "Issues", "Checklists");
        for (Sheet sheet : inProcess.sheets()) {
            assertThat(inImage.sheet(sheet.name()).orElseThrow().cells()).as(sheet.name()).isEqualTo(sheet.cells());
        }
    }

    @Test
    @DisplayName("another major: a non-zero exit with its reason on stderr, and no document")
    void anotherMajor() throws IOException {
        ObjectNode export = (ObjectNode) JSON.readTree(sample());
        export.put("schema_version", "2.0");

        Run run = run(JSON.writeValueAsBytes(export));

        assertThat(run.exitCode()).isEqualTo(2);
        assertThat(run.stderr()).contains("reads major 1 only");
        assertThat(run.output()).as("nothing written").isNull();
    }

    private record Run(int exitCode, String stderr, byte[] output) {}

    /** What {@link ReportPluginRenderer} runs once the signer is verified — its constants, the manifest's bounds. */
    private static Run run(byte[] export) {
        return Workspace.withWorkspace(workspace -> {
            String owner = ContainerRun.ownerOf(workspace.root()).orElseThrow();
            Path input;
            try {
                input = Files.createDirectory(workspace.root().resolve("input"),
                        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
                Files.write(input.resolve(ReportPluginRenderer.EXPORT_FILE), export);
            } catch (IOException unwritable) {
                throw new UncheckedIOException(unwritable);
            }
            ContainerRun run = ContainerRun.of(IMAGE,
                            manifest.command(ReportPluginManifest.INPUT + "/" + ReportPluginRenderer.EXPORT_FILE,
                                    ReportPluginManifest.OUTPUT + "/" + manifest.output()),
                            List.of(ContainerRun.Mount.readOnly(input.toString(), ReportPluginManifest.INPUT)),
                            "report plugin " + manifest.id())
                    .runningAs(owner)
                    .withBoundedOutput(new ContainerRun.BoundedOutput(ReportPluginManifest.OUTPUT,
                            manifest.maxOutputBytes(), PluginScanner.OUTPUT_HOLDER, manifest.output(),
                            ReportPluginRenderer.OUTPUT_INODES))
                    .withTimeout(Duration.ofSeconds(manifest.timeoutSeconds()));
            ContainerRunner.ContainerResult result = RUNNER.run(run);
            ContainerRunner.CollectedOutput output = result.output().orElseThrow();
            assertThat(output.full()).as("within its sixteen inodes and its ceiling").isFalse();
            byte[] bytes = output.file() instanceof ContainerRunner.OutputFile.Read read ? read.bytes() : null;
            return new Run(result.exitCode(), result.stderr() == null ? "" : result.stderr(), bytes);
        });
    }

    private static byte[] sample() {
        try {
            return Files.readAllBytes(PROJECT.resolve("src/test/resources/exports/sample.json"));
        } catch (IOException unreadable) {
            throw new UncheckedIOException(unreadable);
        }
    }
}
