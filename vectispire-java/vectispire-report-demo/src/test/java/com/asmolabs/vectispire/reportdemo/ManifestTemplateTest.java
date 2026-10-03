package com.asmolabs.vectispire.reportdemo;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.reportplugins.ProjectExportSchema;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportMediaType;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportPluginManifest;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The manifest the release publishes (decision 0035 §6), filled the way {@code release.yml} fills it, is one
 * the registry accepts — and calls this plugin the way it expects to be called.
 *
 * <p>The release substitutes two placeholders, the image by digest and the signing identity, which only the
 * tag knows. A template the registry would refuse — a field renamed in R2's shape, an output name not ending
 * in {@code .xlsx}, a timeout out of bounds — would be published, signed, and refused by every installation
 * that pasted it; this fails first.
 */
@DisplayName("the demonstration plugin's published manifest")
class ManifestTemplateTest {

    static final Path TEMPLATE = Path.of("manifest.template.json");

    /** What {@code release.yml}'s publish job writes in place of the placeholders. */
    static String filled() throws IOException {
        return Files.readString(TEMPLATE)
                .replace("{{image}}", "ghcr.io/asmolabs/vectispire-report-demo@sha256:" + "ab".repeat(32))
                .replace("{{identity}}",
                        "https://github.com/asmolabs/vectispire/.github/workflows/release.yml@refs/tags/v1.2.3");
    }

    @Test
    @DisplayName("filled, it is a manifest the registry validates: the R2 shape, export major 1, an .xlsx, signed keyless")
    void validates() throws IOException {
        assertThat(Files.readString(TEMPLATE)).as("the two placeholders the release fills, each once")
                .containsOnlyOnce("{{image}}").containsOnlyOnce("{{identity}}");

        ReportPluginManifest manifest = Fixtures.JSON.readValue(filled(), ReportPluginManifest.class).validated();

        assertThat(manifest.id()).isEqualTo("vectispire-report-demo");
        assertThat(manifest.exportSchema()).isEqualTo(ProjectExportSchema.MAJOR).isEqualTo(ExportDocument.MAJOR);
        assertThat(manifest.mediaType()).isEqualTo(ReportMediaType.XLSX);
        assertThat(manifest.output()).isEqualTo("summary.xlsx");
        assertThat(manifest.signature().issuer()).isEqualTo("https://token.actions.githubusercontent.com");
        assertThat(manifest.signature().publicKey()).isNull();
    }

    @Test
    @DisplayName("its arguments, with the executor's paths in place, are the command this plugin runs")
    void argumentConvention(@TempDir Path directory) throws IOException {
        ReportPluginManifest manifest = Fixtures.JSON.readValue(filled(), ReportPluginManifest.class).validated();
        Path input = Files.write(directory.resolve("export.json"), Fixtures.export("sample.json"));
        Path output = directory.resolve(manifest.output());

        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int code = ReportDemo.run(manifest.command(input.toString(), output.toString()).toArray(String[]::new),
                new PrintStream(err, true, StandardCharsets.UTF_8));

        assertThat(code).as(err.toString(StandardCharsets.UTF_8)).isZero();
        assertThat(Files.size(output)).isPositive().isLessThanOrEqualTo(manifest.maxOutputBytes());
    }
}
