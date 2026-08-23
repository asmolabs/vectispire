package com.asmolabs.zanshin.common.domain.cyclonedx;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;

class CycloneDxDocumentTest {

    private final ObjectMapper json = new ObjectMapper().registerModule(new JavaTimeModule());

    @Test
    void serializesAndDeserializesCycloneDxVex() throws Exception {
        CycloneDxDocument.Component rootComponent = new CycloneDxDocument.Component(
                "pkg:maven/com.asmolabs/zanshin@0.9.0",
                "application",
                "com.asmolabs",
                "zanshin",
                "0.9.0",
                "pkg:maven/com.asmolabs/zanshin@0.9.0",
                "required");

        CycloneDxDocument.Component libComponent = new CycloneDxDocument.Component(
                "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
                "library",
                "org.apache.commons",
                "commons-lang3",
                "3.12.0",
                "pkg:maven/org.apache.commons/commons-lang3@3.12.0",
                "required");

        CycloneDxDocument.Vulnerability vuln = new CycloneDxDocument.Vulnerability(
                "vuln-cve-2023-1234",
                "CVE-2023-1234",
                new CycloneDxDocument.Source("NVD", "https://nvd.nist.gov/vuln/detail/CVE-2023-1234"),
                List.of(new CycloneDxDocument.Rating(new CycloneDxDocument.Source("NVD", null), 7.5, "high", "CVSSv31", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")),
                "A vulnerability in text parser",
                "Detailed description of the issue",
                "Upgrade to 3.14.0",
                new CycloneDxDocument.Analysis("not_affected", "vulnerable_code_not_in_execute_path", "Method is unreachable in target codebase", List.of("will_not_fix")),
                List.of(new CycloneDxDocument.Affects("pkg:maven/org.apache.commons/commons-lang3@3.12.0")));

        CycloneDxDocument doc = new CycloneDxDocument(
                CycloneDxDocument.BOM_FORMAT,
                CycloneDxDocument.SPEC_VERSION,
                "urn:uuid:12345678-1234-5678-1234-567812345678",
                1,
                new CycloneDxDocument.Metadata(
                        Instant.parse("2026-08-23T00:00:00Z"),
                        List.of(new CycloneDxDocument.Tool("AsmoLabs", "Zanshin", "0.9.0")),
                        rootComponent),
                List.of(libComponent),
                List.of(vuln));

        String serialized = json.writeValueAsString(doc);
        assertThat(serialized).contains("\"bomFormat\":\"CycloneDX\"");
        assertThat(serialized).contains("\"specVersion\":\"1.5\"");
        assertThat(serialized).contains("\"analysis\"");
        assertThat(serialized).contains("\"not_affected\"");
        assertThat(serialized).contains("\"bom-ref\":\"pkg:maven/org.apache.commons/commons-lang3@3.12.0\"");

        CycloneDxDocument deserialized = json.readValue(serialized, CycloneDxDocument.class);
        assertThat(deserialized.bomFormat()).isEqualTo("CycloneDX");
        assertThat(deserialized.vulnerabilities()).hasSize(1);
        assertThat(deserialized.vulnerabilities().get(0).analysis().state()).isEqualTo("not_affected");
        assertThat(deserialized.vulnerabilities().get(0).analysis().justification()).isEqualTo("vulnerable_code_not_in_execute_path");
    }
}
