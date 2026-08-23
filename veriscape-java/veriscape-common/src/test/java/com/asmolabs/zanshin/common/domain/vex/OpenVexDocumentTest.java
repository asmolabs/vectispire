package com.asmolabs.zanshin.common.domain.vex;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("OpenVEX v0.2.0 specification adherence")
class OpenVexDocumentTest {

    @Test
    @DisplayName("generates valid OpenVEX statements and document structure")
    void generatesValidOpenVexDocument() {
        OpenVexStatement stmt1 = OpenVexStatement.notAffected(
                "CVE-2022-42889",
                "pkg:maven/org.apache.commons/commons-text@1.9",
                VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
                "Static analysis determined StringSubstitutor is not in the execution call graph");

        OpenVexStatement stmt2 = OpenVexStatement.affected(
                "CVE-2021-44228",
                "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                "Upgrade required before SLA deadline (due in 3 days)");

        OpenVexDocument doc = OpenVexDocument.create(
                "https://zanshin.internal/vex/scans/42/openvex.json",
                Instant.parse("2026-08-22T14:00:00Z"),
                List.of(stmt1, stmt2));

        assertThat(doc.context()).isEqualTo("https://openvex.dev/ns/v0.2.0");
        assertThat(doc.statements()).hasSize(2);
        assertThat(doc.statements().get(0).status()).isEqualTo(VexStatus.NOT_AFFECTED);
        assertThat(doc.statements().get(0).justification()).isEqualTo(VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH);
        assertThat(doc.statements().get(1).status()).isEqualTo(VexStatus.AFFECTED);
    }
}
