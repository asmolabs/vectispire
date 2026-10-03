package com.asmolabs.vectispire.common.domain.reportplugins;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.plugins.InvalidPluginException;
import com.asmolabs.vectispire.common.domain.plugins.PluginSignature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** The report plugin manifest's rules (decision 0035 §2): what is refused, what the digest covers. */
@DisplayName("a report plugin manifest")
class ReportPluginManifestTest {

    static final String IMAGE = "registry.example.internal/reports/summary@sha256:" + "a".repeat(64);
    static final PluginSignature SIGNER = new PluginSignature(
            "https://ci.example.internal/reports/summary/release@refs/tags/v1", "https://ci.example.internal/oidc", null);

    static ReportPluginManifest manifest() {
        return new ReportPluginManifest("summary", "Quarterly summary", IMAGE, 1, List.of("--in", "{input}", "--out",
                "{output}"), "summary.xlsx", ReportMediaType.XLSX, null, null, SIGNER);
    }

    static ReportPluginManifest with(String output, ReportMediaType type, Long maxBytes, Integer timeout,
            PluginSignature signature, Integer major) {
        return new ReportPluginManifest("summary", "Quarterly summary", IMAGE, major, List.of(), output, type, maxBytes,
                timeout, signature);
    }

    @Test
    @DisplayName("takes its defaults: 20 MiB, 120 seconds — and hashes with them")
    void defaults() {
        ReportPluginManifest manifest = manifest().validated();
        assertThat(manifest.maxOutputBytes()).isEqualTo(20L * 1024 * 1024);
        assertThat(manifest.timeoutSeconds()).isEqualTo(120);
        assertThat(manifest.digest()).isEqualTo(new ReportPluginManifest("summary", "Quarterly summary", IMAGE, 1,
                List.of("--in", "{input}", "--out", "{output}"), "summary.xlsx", ReportMediaType.XLSX,
                20L * 1024 * 1024, 120, SIGNER).digest());
    }

    @Test
    @DisplayName("requires a signer — there is no waiver for a plugin whose output the platform signs")
    void signerRequired() {
        assertThatThrownBy(() -> with("summary.xlsx", ReportMediaType.XLSX, null, null, null, 1).validated())
                .isInstanceOf(InvalidPluginException.class)
                .hasMessageContaining("no waiver");
    }

    @Test
    @DisplayName("names a media type from the closed list; HTML and a macro-enabled workbook are not on it")
    void closedMediaTypes() {
        assertThat(ReportMediaType.fromJson("application/pdf")).isEqualTo(ReportMediaType.PDF);
        assertThatThrownBy(() -> ReportMediaType.fromJson("text/html"))
                .isInstanceOf(InvalidPluginException.class)
                .hasMessageContaining("not offered");
        assertThatThrownBy(() -> ReportMediaType.fromJson("application/vnd.ms-excel.sheet.macroEnabled.12"))
                .isInstanceOf(InvalidPluginException.class);
        assertThatThrownBy(() -> with("summary.xlsx", null, null, null, SIGNER, 1).validated())
                .isInstanceOf(InvalidPluginException.class)
                .hasMessageContaining("media_type");
    }

    @ParameterizedTest
    @ValueSource(strings = {"summary.xlsm", "summary.pdf", "summary", "../summary.xlsx", ".xlsx"})
    @DisplayName("writes a bare file name ending with its type's extension")
    void outputMatchesTheType(String output) {
        assertThatThrownBy(() -> with(output, ReportMediaType.XLSX, null, null, SIGNER, 1).validated())
                .isInstanceOf(InvalidPluginException.class);
    }

    @Test
    @DisplayName("bounds its output at 50 MiB and its timeout at 10 to 300 seconds")
    void bounds() {
        with("summary.xlsx", ReportMediaType.XLSX, 50L * 1024 * 1024, 300, SIGNER, 1).validated();
        with("summary.xlsx", ReportMediaType.XLSX, 1L, 10, SIGNER, 1).validated();
        assertThatThrownBy(() -> with("summary.xlsx", ReportMediaType.XLSX, 50L * 1024 * 1024 + 1, null, SIGNER, 1)
                .validated()).isInstanceOf(InvalidPluginException.class).hasMessageContaining("max_output_bytes");
        assertThatThrownBy(() -> with("summary.xlsx", ReportMediaType.XLSX, 0L, null, SIGNER, 1)
                .validated()).isInstanceOf(InvalidPluginException.class);
        assertThatThrownBy(() -> with("summary.xlsx", ReportMediaType.XLSX, null, 301, SIGNER, 1).validated())
                .isInstanceOf(InvalidPluginException.class).hasMessageContaining("timeout");
        assertThatThrownBy(() -> with("summary.xlsx", ReportMediaType.XLSX, null, 9, SIGNER, 1).validated())
                .isInstanceOf(InvalidPluginException.class).hasMessageContaining("timeout");
    }

    @Test
    @DisplayName("declares the export major it reads, and pins its image by digest")
    void majorAndImage() {
        assertThatThrownBy(() -> with("summary.xlsx", ReportMediaType.XLSX, null, null, SIGNER, null).validated())
                .isInstanceOf(InvalidPluginException.class).hasMessageContaining("export_schema");
        assertThatThrownBy(() -> new ReportPluginManifest("summary", "Quarterly summary",
                "registry.example.internal/reports/summary:latest", 1, List.of(), "summary.xlsx", ReportMediaType.XLSX,
                null, null, SIGNER).validated())
                .isInstanceOf(InvalidPluginException.class).hasMessageContaining("digest");
    }

    @Test
    @DisplayName("hashes every field: a different type, ceiling, timeout, major, argument or signer is another digest")
    void digestCoversEveryField() {
        String digest = manifest().digest();
        assertThat(digest).matches("[0-9a-f]{64}");
        List<ReportPluginManifest> others = List.of(
                new ReportPluginManifest("summary", "Quarterly summary", IMAGE, 1, List.of("--in", "{input}", "--out",
                        "{output}"), "summary.ods", ReportMediaType.ODS, null, null, SIGNER),
                new ReportPluginManifest("summary", "Quarterly summary", IMAGE, 2, List.of("--in", "{input}", "--out",
                        "{output}"), "summary.xlsx", ReportMediaType.XLSX, null, null, SIGNER),
                new ReportPluginManifest("summary", "Quarterly summary", IMAGE, 1, List.of("--in", "{input}"),
                        "summary.xlsx", ReportMediaType.XLSX, null, null, SIGNER),
                new ReportPluginManifest("summary", "Quarterly summary", IMAGE, 1, List.of("--in", "{input}", "--out",
                        "{output}"), "summary.xlsx", ReportMediaType.XLSX, 1024L, null, SIGNER),
                new ReportPluginManifest("summary", "Quarterly summary", IMAGE, 1, List.of("--in", "{input}", "--out",
                        "{output}"), "summary.xlsx", ReportMediaType.XLSX, null, 60, SIGNER),
                new ReportPluginManifest("summary", "Quarterly summary", IMAGE, 1, List.of("--in", "{input}", "--out",
                        "{output}"), "summary.xlsx", ReportMediaType.XLSX, null, null,
                        new PluginSignature(SIGNER.identity() + "x", SIGNER.issuer(), null)));
        assertThat(others).extracting(ReportPluginManifest::digest).doesNotContain(digest).doesNotHaveDuplicates();
    }

    @Test
    @DisplayName("travels in the wire form the governor writes, and hashes alike once read back")
    void wireForm() throws Exception {
        ObjectMapper json = new ObjectMapper();
        String written = json.writeValueAsString(manifest());
        assertThat(written).contains("\"export_schema\":1", "\"media_type\":\"" + ReportMediaType.XLSX.wireName() + "\"",
                "\"max_output_bytes\":20971520", "\"timeout_seconds\":120");
        assertThat(json.readValue(written, ReportPluginManifest.class).digest()).isEqualTo(manifest().digest());
    }
}
