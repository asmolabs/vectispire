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

@DisplayName("the OASIS CSAF 2.0 security advisory routes")
class CsafRoutesTest extends ApiTestBase {

    @Autowired
    private Scans scansRepo;

    @Autowired
    private GitRepositories repositoriesRepo;

    @Autowired
    private Findings findingsRepo;

    @Test
    @DisplayName("generates valid OASIS CSAF 2.0 advisory for completed scan")
    void generatesScanCsaf() throws Exception {
        String token = asAdmin();

        RepositoryEntity repo = new RepositoryEntity();
        repo.setName("corp/backend");
        repo.setUrl("https://github.com/corp/backend.git");
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
        finding.setPackageName("netty-codec-http2");
        finding.setPackageVersion("4.1.99.Final");
        finding.setPurl("pkg:maven/io.netty/netty-codec-http2@4.1.99.Final");
        finding.setSource("trivy");
        finding.setSeverity("HIGH");
        finding.setReachability("UNREACHABLE");
        finding.setCreatedAt(Instant.now());
        findingsRepo.save(finding);

        mvc.perform(authenticated(get("/api/v1/csaf/scans/" + scan.getId() + "/csaf.json"), token))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", "attachment; filename=\"scan-" + scan.getId() + "-csaf.json\""))
                .andExpect(jsonPath("$.document.category").value("csaf_vex"))
                .andExpect(jsonPath("$.document.csaf_version").value("2.0"))
                .andExpect(jsonPath("$.vulnerabilities[0].cve").value("CVE-2023-44487"))
                .andExpect(jsonPath("$.vulnerabilities[0].product_status.known_not_affected").isArray());
    }

    @Test
    @DisplayName("generates aggregate CSAF 2.0 document")
    void generatesAggregateCsaf() throws Exception {
        String token = asAdmin();

        mvc.perform(authenticated(get("/api/v1/csaf/aggregate.json"), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.document.csaf_version").value("2.0"))
                .andExpect(jsonPath("$.document.publisher.name").value("Zanshin Control Plane"));
    }
}
