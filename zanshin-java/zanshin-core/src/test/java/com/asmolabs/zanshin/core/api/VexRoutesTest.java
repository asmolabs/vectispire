package com.asmolabs.zanshin.core.api;

import static org.assertj.core.api.Assertions.assertThat;
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

@DisplayName("the OpenVEX advisory routes")
class VexRoutesTest extends ApiTestBase {

    @Autowired
    private Scans scansRepo;

    @Autowired
    private GitRepositories repositoriesRepo;

    @Autowired
    private Findings findingsRepo;

    @Test
    @DisplayName("generates valid OpenVEX v0.2.0 advisory for completed scan")
    void generatesScanOpenVex() throws Exception {
        String token = asAdmin();

        RepositoryEntity repo = new RepositoryEntity();
        repo.setName("corp/portal");
        repo.setUrl("https://github.com/corp/portal.git");
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
        finding.setIdentifier("CVE-2022-42889");
        finding.setPackageName("commons-text");
        finding.setPackageVersion("1.9");
        finding.setPurl("pkg:maven/org.apache.commons/commons-text@1.9");
        finding.setSource("trivy");
        finding.setSeverity("HIGH");
        finding.setReachability("UNREACHABLE");
        finding.setCreatedAt(Instant.now());
        findingsRepo.save(finding);

        mvc.perform(authenticated(get("/api/v1/vex/scans/" + scan.getId() + "/openvex.json"), token))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", "attachment; filename=\"scan-" + scan.getId() + "-openvex.json\""))
                .andExpect(jsonPath("$.['@context']").value("https://openvex.dev/ns/v0.2.0"))
                .andExpect(jsonPath("$.statements[0].vulnerability.name").value("CVE-2022-42889"))
                .andExpect(jsonPath("$.statements[0].status").value("not_affected"))
                .andExpect(jsonPath("$.statements[0].justification").value("vulnerable_code_not_in_execute_path"));
    }

    @Test
    @DisplayName("generates aggregate OpenVEX document for compliance audit")
    void generatesAggregateOpenVex() throws Exception {
        String token = asAdmin();

        mvc.perform(authenticated(get("/api/v1/vex/aggregate.json"), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.['@context']").value("https://openvex.dev/ns/v0.2.0"))
                .andExpect(jsonPath("$.author").value("Zanshin ASPM Control Plane"));
    }
}
