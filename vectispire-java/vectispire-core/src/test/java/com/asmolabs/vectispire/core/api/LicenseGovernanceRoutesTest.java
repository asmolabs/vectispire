package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.licenses.LicensePolicy;
import com.asmolabs.vectispire.common.domain.licenses.LicenseRiskCategory;
import com.asmolabs.vectispire.core.persistence.ComponentEntity;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Components;
import com.asmolabs.vectispire.core.repositories.Findings;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

@DisplayName("the License Governance and Copyleft routes")
class LicenseGovernanceRoutesTest extends ApiTestBase {

    @Autowired
    private Components componentsRepo;

    @Autowired
    private GitRepositories repositoriesRepo;

    @Autowired
    private Scans scansRepo;

    @Autowired
    private Findings findingsRepo;

    @Test
    @DisplayName("retrieves license policy, summary, and inventory with copyleft risk classification")
    void managesLicenseGovernance() throws Exception {
        String adminToken = asAdmin();

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
        // 1. Licences as the cataloguer declares them, one permissive and one copyleft. This test
        // used to seed bare components and let the service *guess* GPL from the name
        // "mysql-connector" — asserting the invention it now refuses to make.
        scan.setSbom("""
                {"artifacts": [
                  {"name": "org.apache.commons:commons-lang3", "version": "3.12.0",
                   "purl": "pkg:maven/org.apache.commons/commons-lang3@3.12.0", "licenses": ["Apache-2.0"]},
                  {"name": "mysql:mysql-connector-j", "version": "8.0.33",
                   "purl": "pkg:maven/mysql/mysql-connector-j@8.0.33", "licenses": ["GPL-2.0"]}]}""");
        scan = scansRepo.save(scan);

        // And one component nothing declares a licence for.
        ComponentEntity undeclared = new ComponentEntity();
        undeclared.setScanId(scan.getId());
        undeclared.setName("com.example:mystery-lib");
        undeclared.setVersion("1.0.0");
        undeclared.setPurl("pkg:maven/com.example/mystery-lib@1.0.0");
        componentsRepo.save(undeclared);

        // 2. Query summary
        mvc.perform(authenticated(get("/api/v1/licenses/summary"), adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalDependencies").isNumber())
                .andExpect(jsonPath("$.breakdownByRisk.PERMISSIVE").isNumber())
                .andExpect(jsonPath("$.breakdownByRisk.STRONG_COPYLEFT").isNumber());

        // 3. Query inventory
        mvc.perform(authenticated(get("/api/v1/licenses/inventory"), adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.packageName == 'mysql:mysql-connector-j')].riskCategory").value("STRONG_COPYLEFT"))
                .andExpect(jsonPath("$[?(@.packageName == 'mysql:mysql-connector-j')].compliant").value(false))
                // Unknown, not MIT: anything unrecognised used to be declared MIT, hence permissive,
                // hence compliant under every policy — cleared precisely because nobody read it.
                .andExpect(jsonPath("$[?(@.packageName == 'com.example:mystery-lib')].license").value("UNKNOWN"))
                .andExpect(jsonPath("$[?(@.packageName == 'com.example:mystery-lib')].riskCategory").value("UNKNOWN"));

        // 4. Update policy to allow STRONG_COPYLEFT
        LicensePolicy updatedPolicy = new LicensePolicy(
                Set.of(LicenseRiskCategory.FORBIDDEN),
                Set.of("GPL-2.0"),
                Set.of());

        mvc.perform(authenticated(put("/api/v1/licenses/policy"), adminToken)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(updatedPolicy)))
                .andExpect(status().isOk());

        // 5. Verify inventory is now compliant
        mvc.perform(authenticated(get("/api/v1/licenses/inventory"), adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.packageName == 'mysql:mysql-connector-j')].compliant").value(true));

        // 6. Query cross-license compatibility matrix and conflicts
        mvc.perform(authenticated(get("/api/v1/licenses/matrix"), adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").isNumber());

        mvc.perform(authenticated(get("/api/v1/licenses/conflicts?proprietary=true"), adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[?(@.packageName == 'mysql:mysql-connector-j')].compatibility").value("INCOMPATIBLE_BLOCKING"));
    }
}
