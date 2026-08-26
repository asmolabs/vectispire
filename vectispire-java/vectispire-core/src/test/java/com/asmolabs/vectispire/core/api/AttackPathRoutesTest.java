package com.asmolabs.vectispire.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.core.persistence.ApiEndpointEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.ApiEndpoints;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

@DisplayName("the Attack Path Visualizer REST routes")
class AttackPathRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositories repositoriesRepo;

    @Autowired
    private Scans scansRepo;

    @Autowired
    private ApiEndpoints apiEndpointsRepo;

    @Autowired
    private Issues issuesRepo;

    @Test
    @DisplayName("generates attack path graph correlating unauthenticated API, critical vulnerability, and secrets")
    void generatesAttackPathGraph() throws Exception {
        String token = asAdmin();

        RepositoryEntity repo = new RepositoryEntity();
        repo.setName("corp/payment-gateway");
        repo.setUrl("https://github.com/corp/payment-gateway.git");
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
        ep.setPath("/api/v1/auth/login");
        ep.setAuthRequired(false);
        ep.setVisibility("PUBLIC");
        ep.setFilePath("src/main/java/AuthController.java");
        ep.setFramework("SPRING_BOOT");
        ep.setCreatedAt(Instant.now());
        apiEndpointsRepo.save(ep);

        IssueEntity vuln = new IssueEntity();
        vuln.setRepoId(repo.getId());
        vuln.setFingerprint("fp-attackpath-vuln");
        vuln.setIdentifier("CVE-2021-44228");
        vuln.setPackageName("log4j-core");
        vuln.setPackageVersion("2.14.1");
        vuln.setType("vulnerability");
        vuln.setSeverity("CRITICAL");
        vuln.setState("open");
        vuln.setTriageStatus("under_review");
        vuln.setReachability("REACHABLE");
        vuln.setCvssScore(10.0);
        vuln.setDescription("Remote Code Execution in Log4j JNDI lookup");
        vuln.setFirstSeenAt(Instant.now());
        vuln.setLastSeenAt(Instant.now());
        vuln.setTimesSeen(1);
        issuesRepo.save(vuln);

        IssueEntity secret = new IssueEntity();
        secret.setRepoId(repo.getId());
        secret.setFingerprint("fp-attackpath-secret");
        secret.setIdentifier("STRIPE_SECRET_KEY");
        secret.setType("secret");
        secret.setSeverity("CRITICAL");
        secret.setState("open");
        secret.setTriageStatus("under_review");
        secret.setFilePath("config/secrets.env");
        secret.setDescription("Hardcoded Stripe secret API key");
        secret.setFirstSeenAt(Instant.now());
        secret.setLastSeenAt(Instant.now());
        secret.setTimesSeen(1);
        issuesRepo.save(secret);

        mvc.perform(authenticated(get("/api/v1/attack-paths/repositories/" + repo.getId()), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.targetName").value("corp/payment-gateway"))
                .andExpect(jsonPath("$.criticalExploitablePaths").value(2))
                .andExpect(jsonPath("$.nodes[?(@.type == 'INTERNET_INGRESS')]").exists())
                .andExpect(jsonPath("$.nodes[?(@.type == 'API_ENDPOINT')]").exists())
                .andExpect(jsonPath("$.nodes[?(@.type == 'VULNERABLE_COMPONENT')]").exists())
                .andExpect(jsonPath("$.nodes[?(@.type == 'SECRET')]").exists())
                .andExpect(jsonPath("$.attackPaths").isArray());

        mvc.perform(authenticated(get("/api/v1/attack-paths/overview"), token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray())
                .andExpect(jsonPath("$[?(@.targetName == 'corp/payment-gateway')]").exists());
    }

    @Test
    @DisplayName("returns 404 for nonexistent repository")
    void returns404ForNonexistent() throws Exception {
        String token = asAdmin();
        mvc.perform(authenticated(get("/api/v1/attack-paths/repositories/999999"), token))
                .andExpect(status().isNotFound());
    }
}
