package com.asmolabs.vectispire.common.domain.exports;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("CSAF 2.0 VEX Export")
class CsafExportTest {

    @Test
    @DisplayName("builds a valid CSAF 2.0 VEX document")
    void buildsCsafDocument() {
        ExportableIssue cve1 = ExportableIssue.builder()
                .id(1L)
                .identifier("CVE-2021-44228")
                .type(FindingType.VULNERABILITY)
                .severity(Severity.CRITICAL)
                .cvssScore(10.0)
                .packageName("log4j-core")
                .packageVersion("2.14.1")
                .purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
                .triageStatus(TriageStatus.NOT_AFFECTED)
                .triageJustification("component_not_present")
                .triageComment("Subsystem removed in deployment.")
                .fixVersions("2.17.1")
                .build();

        ExportableIssue cve2 = ExportableIssue.builder()
                .id(2L)
                .identifier("CVE-2022-22965")
                .type(FindingType.VULNERABILITY)
                .severity(Severity.HIGH)
                .cvssScore(8.8)
                .packageName("spring-beans")
                .packageVersion("5.3.17")
                .triageStatus(TriageStatus.AFFECTED)
                .build();

        Instant now = Instant.parse("2026-08-22T10:00:00Z");
        CsafDocument doc = CsafExport.build(
                List.of(cve1, cve2),
                new CsafExport.Options("my-target", "Security Team", "1.0.0", "https://example.com", now));

        assertThat(doc.document().category()).isEqualTo("csaf_vex");
        assertThat(doc.document().csafVersion()).isEqualTo("2.0");
        assertThat(doc.productTree().fullProductNames()).hasSize(3); // target + 2 packages

        assertThat(doc.vulnerabilities()).hasSize(2);

        CsafDocument.Vulnerability v1 = doc.vulnerabilities().get(0);
        assertThat(v1.cve()).isEqualTo("CVE-2021-44228");
        assertThat(v1.productStatus().knownNotAffected()).isNotEmpty();
        assertThat(v1.flags()).isNotEmpty();
        assertThat(v1.flags().get(0).label()).isEqualTo("component_not_present");

        CsafDocument.Vulnerability v2 = doc.vulnerabilities().get(1);
        assertThat(v2.cve()).isEqualTo("CVE-2022-22965");
        assertThat(v2.productStatus().knownAffected()).isNotEmpty();
    }
}
