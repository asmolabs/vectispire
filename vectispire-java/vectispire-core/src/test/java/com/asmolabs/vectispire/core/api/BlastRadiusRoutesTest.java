package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Findings;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

@DisplayName("the Blast Radius and Dependency Graph explorer routes")
class BlastRadiusRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositories repositoriesRepo;

    @Autowired
    private Scans scansRepo;

    @Autowired
    private Findings findingsRepo;

    @Test
    @DisplayName("explores dependency blast radius for a package")
    void exploresBlastRadius() throws Exception {
        String token = asAdmin();

        RepositoryEntity repo = new RepositoryEntity();
        repo.setName("corp/payment-service");
        repo.setUrl("https://github.com/corp/payment-service.git");
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
        finding.setCvssScore(9.8);
        finding.setIsDirectDependency(true);
        finding.setReachability("REACHABLE");
        finding.setCreatedAt(Instant.now());
        findingsRepo.save(finding);

        mvc.perform(authenticated(get("/api/v1/blast-radius/explore?q=commons-text"), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.query").value("commons-text"))
                .andExpect(jsonPath("$.totalTargetsAffected").value(1))
                .andExpect(jsonPath("$.directUsages").value(1))
                .andExpect(jsonPath("$.blastRadiusScore").isNumber())
                .andExpect(jsonPath("$.targets[0].targetName").value("corp/payment-service"))
                .andExpect(jsonPath("$.graph.nodes").isArray())
                .andExpect(jsonPath("$.graph.edges").isArray());

        mvc.perform(authenticated(get("/api/v1/blast-radius/top-impact?limit=5"), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }
}
