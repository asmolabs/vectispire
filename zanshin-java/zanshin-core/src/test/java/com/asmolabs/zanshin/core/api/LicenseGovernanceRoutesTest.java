package com.asmolabs.zanshin.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.zanshin.common.domain.licenses.LicensePolicy;
import com.asmolabs.zanshin.common.domain.licenses.LicenseRiskCategory;
import com.asmolabs.zanshin.core.persistence.ComponentEntity;
import com.asmolabs.zanshin.core.persistence.FindingEntity;
import com.asmolabs.zanshin.core.persistence.RepositoryEntity;
import com.asmolabs.zanshin.core.persistence.ScanEntity;
import com.asmolabs.zanshin.core.repositories.Components;
import com.asmolabs.zanshin.core.repositories.Findings;
import com.asmolabs.zanshin.core.repositories.GitRepositories;
import com.asmolabs.zanshin.core.repositories.Scans;
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
        scan = scansRepo.save(scan);

        // 1. Create a component with permissive license and another with copyleft license
        ComponentEntity comp1 = new ComponentEntity();
        comp1.setScanId(scan.getId());
        comp1.setName("org.apache.commons:commons-lang3");
        comp1.setVersion("3.12.0");
        comp1.setPurl("pkg:maven/org.apache.commons/commons-lang3@3.12.0");
        componentsRepo.save(comp1);

        ComponentEntity comp2 = new ComponentEntity();
        comp2.setScanId(scan.getId());
        comp2.setName("mysql:mysql-connector-j");
        comp2.setVersion("8.0.33");
        comp2.setPurl("pkg:maven/mysql/mysql-connector-j@8.0.33");
        componentsRepo.save(comp2);

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
                .andExpect(jsonPath("$[?(@.packageName == 'mysql:mysql-connector-j')].compliant").value(false));

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
    }
}
