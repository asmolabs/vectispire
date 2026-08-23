package com.asmolabs.zanshin.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.zanshin.core.persistence.FindingEntity;
import com.asmolabs.zanshin.core.persistence.RepositoryEntity;
import com.asmolabs.zanshin.core.persistence.ScanEntity;
import com.asmolabs.zanshin.core.repositories.Findings;
import com.asmolabs.zanshin.core.repositories.GitRepositories;
import com.asmolabs.zanshin.core.repositories.Scans;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

@DisplayName("the CycloneDX 1.5 BOM-linked VEX routes")
class CycloneDxRoutesTest extends ApiTestBase {

    @Autowired
    private Scans scansRepo;

    @Autowired
    private GitRepositories repositoriesRepo;

    @Autowired
    private Findings findingsRepo;

    @Test
    @DisplayName("generates valid CycloneDX 1.5 SBOM with VEX analysis for scan")
    void generatesScanCycloneDxVex() throws Exception {
        String token = asAdmin();

        RepositoryEntity repo = new RepositoryEntity();
        repo.setName("corp/auth-service");
        repo.setUrl("https://github.com/corp/auth-service.git");
        repo.setBranch("main");
        repo = repositoriesRepo.save(repo);

        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repo.getId());
        scan.setBranch("main");
        scan.setStatus("completed");
        scan.setCreatedAt(Instant.now());
        scan = scansRepo.save(scan);

        FindingEntity finding = new FindingEntity();
        finding.setScanId(scan.getId());
        finding.setType("sca");
        finding.setIdentifier("CVE-2023-44487");
        finding.setPackageName("io.netty/netty-codec-http2");
        finding.setPackageVersion("4.1.99.Final");
        finding.setPurl("pkg:maven/io.netty/netty-codec-http2@4.1.99.Final");
        finding.setSource("trivy");
        finding.setSeverity("HIGH");
        finding.setReachability("UNREACHABLE");
        finding.setCreatedAt(Instant.now());
        findingsRepo.save(finding);

        mvc.perform(authenticated(get("/api/v1/cyclonedx/scans/" + scan.getId() + "/cyclonedx-vex.json"), token))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", "attachment; filename=\"scan-" + scan.getId() + "-cyclonedx-vex.json\""))
                .andExpect(jsonPath("$.bomFormat").value("CycloneDX"))
                .andExpect(jsonPath("$.specVersion").value("1.5"))
                .andExpect(jsonPath("$.vulnerabilities[0].id").value("CVE-2023-44487"))
                .andExpect(jsonPath("$.vulnerabilities[0].analysis").exists());
    }

    @Test
    @DisplayName("generates aggregate CycloneDX VEX document")
    void generatesAggregateCycloneDxVex() throws Exception {
        String token = asAdmin();

        mvc.perform(authenticated(get("/api/v1/cyclonedx/aggregate.json"), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.bomFormat").value("CycloneDX"))
                .andExpect(jsonPath("$.specVersion").value("1.5"))
                .andExpect(jsonPath("$.metadata.tools[0].name").value("Zanshin"));
    }
}
