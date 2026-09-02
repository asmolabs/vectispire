package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.core.persistence.ApiContractEntity;
import com.asmolabs.vectispire.core.persistence.ApiEndpointEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.ApiContracts;
import com.asmolabs.vectispire.core.repositories.ApiEndpoints;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

@DisplayName("the API Inventory & Attack Surface REST routes")
class ApiInventoryRoutesTest extends ApiTestBase {

    @Autowired
    private ApiEndpoints apiEndpointsRepo;

    @Autowired
    private ApiContracts apiContractsRepo;

    @Autowired
    private GitRepositories repositoriesRepo;

    @Autowired
    private Scans scansRepo;

    @Test
    @DisplayName("returns global attack surface summary and high risk exposed endpoints")
    void returnsGlobalAttackSurface() throws Exception {
        String token = asAdmin();

        RepositoryEntity repo = new RepositoryEntity();
        repo.setName("corp/order-service");
        repo.setUrl("https://github.com/corp/order-service.git");
        repo.setBranch("main");
        repo = repositoriesRepo.save(repo);

        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repo.getId());
        scan.setBranch("main");
        scan.setStatus("completed");
        scan.setCreatedAt(Instant.now());
        scan = scansRepo.save(scan);

        ApiEndpointEntity ep1 = new ApiEndpointEntity();
        ep1.setScanId(scan.getId());
        ep1.setRepositoryId(repo.getId());
        ep1.setHttpMethod("GET");
        ep1.setPath("/public/v1/orders");
        ep1.setAuthRequired(false);
        ep1.setVisibility("PUBLIC");
        ep1.setFramework("SPRING_BOOT");
        ep1.setCreatedAt(Instant.now());
        apiEndpointsRepo.save(ep1);

        ApiEndpointEntity ep2 = new ApiEndpointEntity();
        ep2.setScanId(scan.getId());
        ep2.setRepositoryId(repo.getId());
        ep2.setHttpMethod("POST");
        ep2.setPath("/actuator/env");
        ep2.setAuthRequired(false);
        ep2.setVisibility("INTERNAL");
        ep2.setFramework("SPRING_BOOT");
        ep2.setCreatedAt(Instant.now());
        apiEndpointsRepo.save(ep2);

        mvc.perform(authenticated(get("/api/v1/attack-surface"), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalEndpoints").isNumber())
                .andExpect(jsonPath("$.highRiskEndpoints").isArray());
    }

    @Test
    @DisplayName("returns repository API endpoints, contracts, and shadow API status")
    void returnsRepositoryApis() throws Exception {
        String token = asAdmin();

        RepositoryEntity repo = new RepositoryEntity();
        repo.setName("corp/user-api");
        repo.setUrl("https://github.com/corp/user-api.git");
        repo.setBranch("main");
        repo = repositoriesRepo.save(repo);

        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repo.getId());
        scan.setBranch("main");
        scan.setStatus("completed");
        scan.setCreatedAt(Instant.now());
        scan = scansRepo.save(scan);

        ApiEndpointEntity ep = new ApiEndpointEntity();
        ep.setScanId(scan.getId());
        ep.setRepositoryId(repo.getId());
        ep.setHttpMethod("GET");
        ep.setPath("/api/v1/users");
        ep.setAuthRequired(true);
        ep.setAuthType("BEARER");
        ep.setVisibility("PUBLIC");
        ep.setFilePath("UserController.java");
        ep.setLineNumber(15);
        ep.setFramework("SPRING_BOOT");
        ep.setCreatedAt(Instant.now());
        apiEndpointsRepo.save(ep);

        ApiContractEntity contract = new ApiContractEntity();
        contract.setRepositoryId(repo.getId());
        contract.setScanId(scan.getId());
        contract.setContractPath("openapi.yaml");
        contract.setFormat("OPENAPI_V3");
        contract.setTitle("User Service API");
        contract.setVersion("1.0.0");
        contract.setEndpointsCount(1);
        contract.setCreatedAt(Instant.now());
        apiContractsRepo.save(contract);

        mvc.perform(authenticated(get("/api/v1/repositories/" + repo.getId() + "/apis"), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.repositoryId").value(repo.getId()))
                .andExpect(jsonPath("$.endpoints[0].path").value("/api/v1/users"))
                .andExpect(jsonPath("$.contracts[0].title").value("User Service API"));
    }

    @Test
    @DisplayName("exports synthesized OpenAPI specification for a repository")
    void exportsSynthesizedOpenApi() throws Exception {
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

        ApiEndpointEntity ep = new ApiEndpointEntity();
        ep.setScanId(scan.getId());
        ep.setRepositoryId(repo.getId());
        ep.setHttpMethod("POST");
        ep.setPath("/api/v1/payments");
        ep.setAuthRequired(true);
        ep.setVisibility("PUBLIC");
        ep.setFramework("SPRING_BOOT");
        ep.setCreatedAt(Instant.now());
        apiEndpointsRepo.save(ep);

        mvc.perform(authenticated(get("/api/v1/repositories/" + repo.getId() + "/apis/export/openapi"), token))
                .andExpect(status().isOk())
                .andExpect(header().string("Content-Disposition", "attachment; filename=\"openapi-repository-" + repo.getId() + ".json\""))
                .andExpect(jsonPath("$.openapi").value("3.0.3"))
                .andExpect(jsonPath("$.paths['/api/v1/payments'].post").exists());
    }

    @Test
    @DisplayName("clears attack surface globally and per repository")
    void clearsAttackSurface() throws Exception {
        String token = asAdmin();

        RepositoryEntity repo = new RepositoryEntity();
        repo.setName("corp/auth-service");
        repo.setUrl("https://github.com/corp/auth-service.git");
        repo.setBranch("main");
        repo = repositoriesRepo.save(repo);

        // **A real scan, not a number.** These two endpoints used to be attached to scans 999 and
        // 1000, which never existed — the row was an orphan the moment it was written, and the
        // engine accepted it because SQLite enforces no foreign key until the pragma is issued.
        // Now that it is, the fabrication is refused, which is the point of enforcing it.
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repo.getId());
        scan.setBranch("main");
        scan.setStatus("completed");
        scan.setCreatedAt(Instant.now());
        scan = scansRepo.save(scan);

        ApiEndpointEntity ep = new ApiEndpointEntity();
        ep.setScanId(scan.getId());
        ep.setRepositoryId(repo.getId());
        ep.setHttpMethod("GET");
        ep.setPath("/api/v1/ping");
        ep.setAuthRequired(false);
        ep.setVisibility("PUBLIC");
        ep.setFramework("SPRING");
        ep.setCreatedAt(Instant.now());
        apiEndpointsRepo.save(ep);

        mvc.perform(authenticated(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete("/api/v1/repositories/" + repo.getId() + "/apis"), token))
                .andExpect(status().isNoContent());

        mvc.perform(authenticated(get("/api/v1/repositories/" + repo.getId() + "/apis"), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.endpoints").isEmpty());

        ScanEntity second = new ScanEntity();
        second.setRepoId(repo.getId());
        second.setBranch("main");
        second.setStatus("completed");
        second.setCreatedAt(Instant.now());
        second = scansRepo.save(second);

        ApiEndpointEntity ep2 = new ApiEndpointEntity();
        ep2.setScanId(second.getId());
        ep2.setRepositoryId(repo.getId());
        ep2.setHttpMethod("GET");
        ep2.setPath("/api/v1/health");
        ep2.setAuthRequired(false);
        ep2.setVisibility("PUBLIC");
        ep2.setFramework("SPRING");
        ep2.setCreatedAt(Instant.now());
        apiEndpointsRepo.save(ep2);

        mvc.perform(authenticated(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete("/api/v1/attack-surface"), token))
                .andExpect(status().isNoContent());

        mvc.perform(authenticated(get("/api/v1/attack-surface"), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalEndpoints").value(0));
    }
}
