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

    /**
     * A graph is a picture, and a picture of four hundred nodes is not one.
     *
     * <p>Forty critical vulnerabilities on one repository, well past the ten a target contributes.
     * The node ceiling is what bites here: this drew forty-two nodes before the cut.
     *
     * <p><b>The risk score is pinned beside it, and the honest reason is narrower than it looks.</b>
     * {@code calculateRiskScore} saturates both issue terms — {@code Math.min(3, vulnCount)} and a
     * secret count that reaches the hundred ceiling at four — so with a cut of ten the score
     * provably cannot move, whether it is computed from what was found or from what was drawn.
     * The service computes it from what was found regardless, because that stops being merely
     * equivalent the moment somebody lowers the ceiling or reweights the formula. This assertion
     * is what would catch that: it fails if the ceiling drops below three, or if the score starts
     * following the drawing.
     */
    @Test
    @DisplayName("a target contributes a bounded number of nodes, and the risk score ignores the cut")
    void theGraphIsBoundedAndTheScoreIsNot() throws Exception {
        String token = asAdmin();

        RepositoryEntity repo = new RepositoryEntity();
        repo.setName("corp/very-exposed");
        repo.setUrl("https://example.invalid/very-exposed.git");
        repo.setBranch("main");
        repo = repositoriesRepo.save(repo);

        for (int index = 0; index < 40; index++) {
            IssueEntity issue = new IssueEntity();
            issue.setRepoId(repo.getId());
            issue.setType("sca");
            issue.setIdentifier("CVE-2031-" + index);
            issue.setSeverity("CRITICAL");
            issue.setPackageName("pkg-" + index);
            issue.setState("open");
            issue.setTriageStatus("untriaged");
            issue.setFingerprint("fp-exposed-" + index);
            issue.setFirstSeenAt(Instant.now());
            issue.setLastSeenAt(Instant.now());
            issuesRepo.save(issue);
        }

        mvc.perform(authenticated(get("/api/v1/attack-paths/repositories/" + repo.getId()), token))
                .andExpect(status().isOk())
                // Ingress, database sink and at most ten vulnerabilities — not forty-two.
                .andExpect(jsonPath("$.nodes.length()").value(org.hamcrest.Matchers.lessThanOrEqualTo(20)))
                .andExpect(jsonPath("$.nodes[?(@.type == 'VULNERABILITY')]")
                        .value(org.hamcrest.Matchers.hasSize(org.hamcrest.Matchers.lessThanOrEqualTo(10))))
                // min(3, 40) * 10, with no unauthenticated endpoint and no secret in the fixture.
                // The same number the uncut graph produced.
                .andExpect(jsonPath("$.riskScore").value(30));
    }

    @Test
    @DisplayName("returns 404 for nonexistent repository")
    void returns404ForNonexistent() throws Exception {
        String token = asAdmin();
        mvc.perform(authenticated(get("/api/v1/attack-paths/repositories/999999"), token))
                .andExpect(status().isNotFound());
    }
}
