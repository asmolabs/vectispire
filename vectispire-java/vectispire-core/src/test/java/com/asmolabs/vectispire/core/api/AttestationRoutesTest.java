package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

@DisplayName("the attestation routes")
class AttestationRoutesTest extends ApiTestBase {

    @Autowired
    private Scans scans;

    @Test
    @DisplayName("generates in-toto attestation for a scan")
    void generatesAttestation() throws Exception {
        ScanEntity scan = new ScanEntity();
        scan.setStatus("completed");
        scan.setBranch("main");
        scan.setCreatedAt(Instant.now());
        scan.setFindingsCount(0);
        scan.setSbom("{\"bomFormat\":\"CycloneDX\"}");
        ScanEntity saved = scans.save(scan);

        mvc.perform(authenticated(get("/api/v1/attestations/scans/" + saved.getId()), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$._type").value("https://in-toto.io/Statement/v0.1"))
                .andExpect(jsonPath("$.predicateType").value("https://vectispire.dev/attestation/v1"))
                .andExpect(jsonPath("$.predicate.policy.gatePassed").value(true));
    }
}
