package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.core.inventory.persistence.ComponentEntity;
import com.asmolabs.vectispire.core.inventory.persistence.ComponentRepository;
import com.asmolabs.vectispire.core.scanning.persistence.FindingEntity;
import com.asmolabs.vectispire.core.scanning.persistence.FindingRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

@DisplayName("the SBOM diff routes")
class SbomDiffRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private ComponentRepository components;

    @Autowired
    private FindingRepository findings;

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
        // The scan's target and instant, as ComponentInventory copies them (V61).
        ScanEntity scanOfC1 = scans.findById(scan1.getId()).orElseThrow();
        c1.setRepoId(scanOfC1.getRepoId());
        c1.setContainerId(scanOfC1.getContainerId());
        c1.setScanCreatedAt(scanOfC1.getCreatedAt());
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
        // The scan's target and instant, as ComponentInventory copies them (V61).
        ScanEntity scanOfC2 = scans.findById(scan2.getId()).orElseThrow();
        c2.setRepoId(scanOfC2.getRepoId());
        c2.setContainerId(scanOfC2.getContainerId());
        c2.setScanCreatedAt(scanOfC2.getCreatedAt());
        c2.setName("jackson-databind");
        c2.setVersion("2.14.0");
        c2.setType("npm");
        components.save(c2);

        ComponentEntity c3 = new ComponentEntity();
        c3.setScanId(scan2.getId());
        // The scan's target and instant, as ComponentInventory copies them (V61).
        ScanEntity scanOfC3 = scans.findById(scan2.getId()).orElseThrow();
        c3.setRepoId(scanOfC3.getRepoId());
        c3.setContainerId(scanOfC3.getContainerId());
        c3.setScanCreatedAt(scanOfC3.getCreatedAt());
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

    @Test
    @DisplayName("reads each licence from the SBOM and calls an undeclared one unknown — never guessed from the name")
    void licencesAreReadNotGuessed() throws Exception {
        RepositoryEntity repo = repository("licences-read");
        // No component rows: the diff reads the SBOM itself. "commit-graph" holds "mit", "spring-core" was
        // Apache-2.0 and "gpl-tools" GPL-3.0 by name; none of them declares a licence in the first scan.
        long from = scan(repo, "1.0.0", 7200, """
                {"artifacts":[{"name":"commit-graph","version":"1.0"},{"name":"spring-core","version":"6.0"},
                 {"name":"gpl-tools","version":"2.0"}]}""").getId();
        long to = scan(repo, "1.1.0", 3600, """
                {"artifacts":[{"name":"commit-graph","version":"1.0"},{"name":"spring-core","version":"6.0"},
                 {"name":"gpl-tools","version":"2.0","licenses":[{"value":"MIT"},{"value":"BSD-3-Clause"}]},
                 {"name":"summit-ui","version":"0.1"}]}""").getId();

        mvc.perform(authenticated(get("/api/v1/sbom/diff")
                .param("fromScanId", String.valueOf(from))
                .param("toScanId", String.valueOf(to)), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.licenseChangedCount").value(1))
                .andExpect(jsonPath("$.componentDeltas[?(@.name == 'gpl-tools')].oldLicense").value("UNKNOWN"))
                .andExpect(jsonPath("$.componentDeltas[?(@.name == 'gpl-tools')].newLicense").value("MIT OR BSD-3-Clause"))
                .andExpect(jsonPath("$.componentDeltas[?(@.name == 'summit-ui')].newLicense").value("UNKNOWN"))
                .andExpect(jsonPath("$.componentDeltas[?(@.name == 'commit-graph')]").isEmpty())
                .andExpect(jsonPath("$.componentDeltas[?(@.name == 'spring-core')]").isEmpty());
    }

    @Test
    @DisplayName("takes a component row's licence from its build, else from the scanner's SBOM, else unknown")
    void aComponentRowsLicence() throws Exception {
        RepositoryEntity repo = repository("licences-rows");
        ScanEntity from = scan(repo, "1.0.0", 7200, """
                {"artifacts":[{"name":"commons-io","version":"2.11.0","licenses":["Apache-2.0"]}]}""");
        component(from, "commons-io", "2.11.0", null);
        component(from, "express", "4.0.0", null);
        // The scanner reads another licence for the same version: a change it declared, not one guessed.
        ScanEntity to = scan(repo, "1.1.0", 3600, """
                {"artifacts":[{"name":"commons-io","version":"2.11.0","licenses":["MIT"]}]}""");
        component(to, "commons-io", "2.11.0", null);
        component(to, "express", "4.0.0", "BSD-2-Clause");

        mvc.perform(authenticated(get("/api/v1/sbom/diff")
                .param("fromScanId", String.valueOf(from.getId()))
                .param("toScanId", String.valueOf(to.getId())), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.licenseChangedCount").value(2))
                .andExpect(jsonPath("$.componentDeltas[?(@.name == 'express')].oldLicense").value("UNKNOWN"))
                .andExpect(jsonPath("$.componentDeltas[?(@.name == 'express')].newLicense").value("BSD-2-Clause"))
                .andExpect(jsonPath("$.componentDeltas[?(@.name == 'commons-io')].oldLicense").value("Apache-2.0"))
                .andExpect(jsonPath("$.componentDeltas[?(@.name == 'commons-io')].newLicense").value("MIT"));
    }

    @Test
    @DisplayName("refuses a comparison whose SBOM cannot be read, rather than answering no change")
    void anUnreadableSbomIsNotAnEmptyOne() throws Exception {
        RepositoryEntity repo = repository("licences-unreadable");
        long from = scan(repo, "1.0.0", 7200, "{\"artifacts\":[{\"name\":\"left-pad\"").getId();
        long to = scan(repo, "1.1.0", 3600, "{\"artifacts\":[{\"name\":\"left-pad\"").getId();

        mvc.perform(authenticated(get("/api/v1/sbom/diff")
                .param("fromScanId", String.valueOf(from))
                .param("toScanId", String.valueOf(to)), asAdmin()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.type").value("urn:vectispire:problem:sbom-unreadable"))
                .andExpect(jsonPath("$.detail").value(org.hamcrest.Matchers.containsString("scan " + from)));
        mvc.perform(authenticated(get("/api/v1/sbom/diff/latest")
                .param("repoId", String.valueOf(repo.getId())), asAdmin()))
                .andExpect(status().isConflict());
    }

    private RepositoryEntity repository(String name) {
        RepositoryEntity repo = new RepositoryEntity();
        repo.setName(name);
        repo.setUrl("https://example.invalid/" + name + "-" + System.nanoTime() + ".git");
        repo.setBranch("main");
        return repositories.save(repo);
    }

    private ScanEntity scan(RepositoryEntity repo, String version, long secondsAgo, String sbom) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repo.getId());
        scan.setBranch("main");
        scan.setStatus("completed");
        scan.setVersion(version);
        scan.setCreatedAt(Instant.now().minusSeconds(secondsAgo));
        scan.setSbom(sbom);
        return scans.save(scan);
    }

    private void component(ScanEntity scan, String name, String version, String declaredLicense) {
        ComponentEntity component = new ComponentEntity();
        component.setScanId(scan.getId());
        component.setRepoId(scan.getRepoId());
        component.setScanCreatedAt(scan.getCreatedAt());
        component.setName(name);
        component.setVersion(version);
        component.setType("java-archive");
        component.setDeclaredLicense(declaredLicense);
        components.save(component);
    }
}
