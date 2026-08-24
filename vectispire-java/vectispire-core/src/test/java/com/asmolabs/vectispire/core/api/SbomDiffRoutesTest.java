package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.core.persistence.ComponentEntity;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Components;
import com.asmolabs.vectispire.core.repositories.Findings;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

@DisplayName("the SBOM diff routes")
class SbomDiffRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Scans scans;

    @Autowired
    private Components components;

    @Autowired
    private Findings findings;

    @Test
    @DisplayName("computes differential between two scans")
    void computesSbomDiff() throws Exception {
        RepositoryEntity repo = new RepositoryEntity();
        repo.setName("test-sbom-repo");
        repo.setUrl("https://github.com/asmolabs/test.git");
        repo.setBranch("main");
        repo = repositories.save(repo);

        ScanEntity scan1 = new ScanEntity();
        scan1.setRepoId(repo.getId());
        scan1.setBranch("main");
        scan1.setStatus("completed");
        scan1.setVersion("1.0.0");
        scan1.setCreatedAt(Instant.now().minusSeconds(3600));
        scan1 = scans.save(scan1);

        ComponentEntity c1 = new ComponentEntity();
        c1.setScanId(scan1.getId());
        c1.setName("jackson-databind");
        c1.setVersion("2.13.0");
        c1.setType("npm");
        components.save(c1);

        FindingEntity f1 = new FindingEntity();
        f1.setScanId(scan1.getId());
        f1.setIdentifier("CVE-2020-36518");
        f1.setSeverity("critical");
        f1.setType("vulnerability");
        f1.setPackageName("jackson-databind");
        f1.setPackageVersion("2.13.0");
        f1.setCreatedAt(Instant.now());
        f1.setFilePath("pom.xml");
        f1.setSource("grype");
        f1.setLine(10);
        findings.save(f1);

        ScanEntity scan2 = new ScanEntity();
        scan2.setRepoId(repo.getId());
        scan2.setBranch("main");
        scan2.setStatus("completed");
        scan2.setVersion("1.1.0");
        scan2.setCreatedAt(Instant.now());
        scan2 = scans.save(scan2);

        ComponentEntity c2 = new ComponentEntity();
        c2.setScanId(scan2.getId());
        c2.setName("jackson-databind");
        c2.setVersion("2.14.0");
        c2.setType("npm");
        components.save(c2);

        ComponentEntity c3 = new ComponentEntity();
        c3.setScanId(scan2.getId());
        c3.setName("commons-io");
        c3.setVersion("2.11.0");
        c3.setType("npm");
        components.save(c3);

        mvc.perform(authenticated(get("/api/v1/sbom/diff")
                .param("fromScanId", String.valueOf(scan1.getId()))
                .param("toScanId", String.valueOf(scan2.getId())), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.fromScanId").value(scan1.getId()))
                .andExpect(jsonPath("$.toScanId").value(scan2.getId()))
                .andExpect(jsonPath("$.addedCount").value(1))
                .andExpect(jsonPath("$.versionChangedCount").value(1))
                .andExpect(jsonPath("$.resolvedCveCount").value(1))
                .andExpect(jsonPath("$.componentDeltas").isArray());

        mvc.perform(authenticated(get("/api/v1/sbom/diff/latest")
                .param("repoId", String.valueOf(repo.getId())), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.toScanId").value(scan2.getId()));
    }
}
