package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.io.ByteArrayInputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
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
                .andExpect(header().string("Content-Disposition", "attachment; filename=\"vectispire-audit-evidence-bundle.zip\""))
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
                "00_vectispire_public_key.pub",
                "01_compliance_frameworks.json",
                "02_immutable_audit_log.jsonl",
                "03_triage_and_exemptions.json",
                "05_openvex_advisory.json",
                "05_openvex_advisory.json.sig",
                "06_csaf_2_0_vex.json",
                "08_cyclonedx_1_5_vex.json",
                // The process sections. Asserted here rather than only in ProcessEvidenceTest
                // because a service nothing calls is a service that is not wired, and no test of
                // the service itself can see that the bundle stopped packaging it.
                "09_gate_verdict_register.json",
                "10_exception_register.json",
                "11_remediation_timeliness.json",
                "12_control_coverage.json",
                "13_statement_of_applicability.json",
                "14_compliance_progression.json");
    }

    @Autowired
    private ScanRepository scans;

    @Autowired
    private GitRepositoryRepository repositories;

    @Test
    @DisplayName("an attested scan ships its statement and envelope; one that cannot be attested ships the reason")
    void attestationsAndRefusalsAreBothInTheBundle() throws Exception {
        // The loop that packs attestations ended in `catch (Exception ignored) {}`: a statement that
        // could not be built vanished from the archive, and nothing in it said a scan was missing.
        RepositoryEntity repository = new RepositoryEntity();
        repository.setName("corp/payments");
        repository.setUrl("https://example.invalid/corp/payments.git");
        repository.setBranch("main");
        long repoId = repositories.save(repository).getId();
        long attested = scan(repoId, "{\"artifacts\":[]}");
        long refused = scan(repoId, null);

        byte[] zip = mvc.perform(authenticated(get("/api/v1/compliance/evidence-bundle.zip"), asAdmin()))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsByteArray();

        List<String> names = new ArrayList<>();
        String reason = null;
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(zip))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                names.add(entry.getName());
                if (entry.getName().equals("04_attestations/scan_" + refused + "_not_attested.txt")) {
                    reason = new String(zis.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                }
            }
        }

        assertThat(names).contains(
                "04_attestations/scan_" + attested + "_in_toto.json",
                "04_attestations/scan_" + attested + "_in_toto.dsse.json",
                "04_attestations/scan_" + refused + "_not_attested.txt");
        assertThat(reason).contains("recorded no SBOM");
    }

    @Test
    @DisplayName("a key restricted to one target takes its own archive: estate-wide sections withheld, and said")
    void aRestrictedKeyTakesItsOwnArchive() throws Exception {
        long mine = repository("corp/mine");
        long other = repository("corp/other");
        scan(mine, "{\"artifacts\":[{\"name\":\"lib-mine\",\"version\":\"1\",\"licenses\":[\"MIT\"]}]}");
        scan(other, "{\"artifacts\":[{\"name\":\"lib-other\",\"version\":\"1\",\"licenses\":[\"GPL-3.0\"]},"
                + "{\"name\":\"lib-other-2\",\"version\":\"1\",\"licenses\":[\"AGPL-3.0\"]}]}");
        String key = issueKey(Map.of("name", "one-product", "scopes", List.of("export"),
                "target_kind", "repository", "target_id", mine));

        Map<String, byte[]> archive = unzip(mvc.perform(authenticated(
                        get("/api/v1/compliance/evidence-bundle.zip"), key))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsByteArray());

        assertThat(archive).doesNotContainKeys("02_immutable_audit_log.jsonl", "14_compliance_progression.json")
                .containsKeys("manifest.json", "07_license_compliance.json", "13_statement_of_applicability.json");
        com.fasterxml.jackson.databind.JsonNode manifest = json.readTree(archive.get("manifest.json"));
        assertThat(manifest.path("withheld").findValuesAsText("path"))
                .containsExactlyInAnyOrder("02_immutable_audit_log.jsonl", "14_compliance_progression.json");
        assertThat(manifest.path("totalAuditLogEntries").isNull()).isTrue();
        assertThat(json.readTree(archive.get("07_license_compliance.json")).path("totalDependencies").asLong())
                .as("the licence summary counts the key's target only")
                .isEqualTo(1);

        // And the whole archive for an unrestricted key, so the narrowing is the restriction's.
        String whole = issueKey(Map.of("name", "archive", "scopes", List.of("export")));
        Map<String, byte[]> full = unzip(mvc.perform(authenticated(
                        get("/api/v1/compliance/evidence-bundle.zip"), whole))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsByteArray());
        assertThat(full).containsKeys("02_immutable_audit_log.jsonl", "14_compliance_progression.json");
        assertThat(json.readTree(full.get("manifest.json")).path("withheld")).isEmpty();
        assertThat(json.readTree(full.get("07_license_compliance.json")).path("totalDependencies").asLong())
                .isEqualTo(3);
    }

    private long repository(String name) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setName(name);
        repository.setUrl("https://example.invalid/" + name + "-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    private String issueKey(Map<String, Object> body) throws Exception {
        String response = mvc.perform(authenticated(
                                org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/api/v1/api-keys"),
                                asAdmin())
                        .contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                        .content(write(body)))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
        return json.readTree(response).get("secret").asText();
    }

    private static Map<String, byte[]> unzip(byte[] zip) throws java.io.IOException {
        Map<String, byte[]> entries = new java.util.LinkedHashMap<>();
        try (ZipInputStream zis = new ZipInputStream(new ByteArrayInputStream(zip))) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                entries.put(entry.getName(), zis.readAllBytes());
            }
        }
        return entries;
    }

    private long scan(long repoId, String sbom) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setStatus("completed");
        scan.setBranch("main");
        scan.setCreatedAt(java.time.Instant.now());
        scan.setSbom(sbom);
        return scans.save(scan).getId();
    }
}
