package com.asmolabs.zanshin.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MvcResult;

@DisplayName("the certified audit evidence vault zip export route")
class EvidenceVaultRoutesTest extends ApiTestBase {

    @Test
    @DisplayName("exports a fully-formed evidence bundle ZIP with manifest and audit trail")
    void exportsEvidenceVaultZip() throws Exception {
        String token = asAdmin();

        MvcResult result = mvc.perform(authenticated(get("/api/v1/compliance/evidence-bundle.zip"), token))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Type", "application/zip"))
                .andExpect(header().string("Content-Disposition", "attachment; filename=\"zanshin-audit-evidence-bundle.zip\""))
                .andReturn();

        byte[] zipBytes = result.getResponse().getContentAsByteArray();
        assertThat(zipBytes).isNotEmpty();

        List<String> entryNames = new ArrayList<>();
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(zipBytes))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                entryNames.add(entry.getName());
                zis.closeEntry();
            }
        }

        assertThat(entryNames).contains(
                "manifest.json",
                "manifest.json.sig",
                "00_zanshin_public_key.pub",
                "01_compliance_frameworks.json",
                "02_immutable_audit_log.jsonl",
                "03_triage_and_exemptions.json",
                "05_openvex_advisory.json",
                "05_openvex_advisory.json.sig",
                "06_csaf_2_0_vex.json",
                "08_cyclonedx_1_5_vex.json");
    }
}
