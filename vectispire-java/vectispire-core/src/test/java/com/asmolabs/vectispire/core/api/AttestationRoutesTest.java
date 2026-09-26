package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.core.gate.persistence.GateVerdictEntity;
import com.asmolabs.vectispire.core.gate.persistence.GateVerdicts;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Findings;
import com.asmolabs.vectispire.core.repositories.Scans;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.Containers;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositories;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.info.BuildProperties;

/**
 * The in-toto statement, field by field, against what was actually recorded.
 *
 * <p>The only test this route had asserted {@code gatePassed: true} on a scan attached to no target
 * — the invented verdict itself, pinned as the expected output. Every assertion below is about a
 * claim a third party verifying the statement would act on.
 */
@DisplayName("the in-toto attestation of a scan")
class AttestationRoutesTest extends ApiTestBase {

    private static final String SBOM = "{\"artifacts\":[{\"name\":\"lodash\",\"version\":\"4.17.21\"}]}";

    private static final ObjectMapper JSON = new ObjectMapper();

    @Autowired
    private Scans scans;

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Containers containers;

    @Autowired
    private Findings findings;

    @Autowired
    private GateVerdicts verdicts;

    @Autowired
    private BuildProperties build;

    private String admin;

    private RepositoryEntity repository;

    @BeforeEach
    void setUp() throws Exception {
        admin = asAdmin();
        repository = new RepositoryEntity();
        repository.setName("corp/payments");
        repository.setUrl("https://example.invalid/corp/payments.git");
        repository.setBranch("main");
        repository = repositories.save(repository);
    }

    @Test
    @DisplayName("names the SBOM by its digest, the build by its version, and says nothing of a gate nobody asked")
    void theSubjectIsTheSbom() throws Exception {
        ScanEntity scan = scan(repository.getId(), null, "completed", SBOM, Instant.now().minusSeconds(600));

        JsonNode statement = attestation(scan.getId());

        JsonNode subject = statement.path("subject").get(0);
        assertThat(subject.path("digest").path("sha256").asText()).isEqualTo(Digests.sha256Hex(SBOM));
        assertThat(subject.path("name").asText()).isEqualTo("corp/payments/sbom-scan-" + scan.getId() + ".json");
        assertThat(statement.path("predicate").path("builder").path("version").asText()).isEqualTo(build.getVersion());
        // No verdict recorded: the old statement said "passed" under a policy that did not exist.
        assertThat(statement.path("predicate").path("policy").isNull() || statement.path("predicate").path("policy").isMissingNode())
                .isTrue();
    }

    @Test
    @DisplayName("carries the verdict the gate recorded between this scan and the next, as the gate recorded it")
    void theRecordedVerdict() throws Exception {
        Instant scanned = Instant.now().minus(Duration.ofHours(2));
        ScanEntity scan = scan(repository.getId(), null, "completed", SBOM, scanned);
        verdict(repository.getId(), null, false, scanned.plus(Duration.ofMinutes(5)), "target", 4L);

        JsonNode policy = attestation(scan.getId()).path("predicate").path("policy");

        assertThat(policy.path("gatePassed").asBoolean(true)).isFalse();
        assertThat(policy.path("enforcedPolicy").asText()).isEqualTo("target");
        assertThat(policy.path("policyVersion").asLong()).isEqualTo(4L);
        assertThat(policy.path("violations").get(0).asText()).startsWith("3 issue(s) over the policy");
    }

    @Test
    @DisplayName("does not borrow a verdict recorded after the next scan — that one judged a different backlog")
    void aLaterVerdictIsNotThisScans() throws Exception {
        Instant first = Instant.now().minus(Duration.ofHours(3));
        ScanEntity scan = scan(repository.getId(), null, "completed", SBOM, first);
        Instant second = first.plus(Duration.ofHours(1));
        scan(repository.getId(), null, "completed", SBOM, second);
        verdict(repository.getId(), null, true, second.plus(Duration.ofMinutes(5)), "global", 1L);

        JsonNode policy = attestation(scan.getId()).path("predicate").path("policy");

        assertThat(policy.isNull() || policy.isMissingNode()).isTrue();
    }

    @Test
    @DisplayName("counts the scan's actively exploited and secret findings instead of writing zero")
    void realCounts() throws Exception {
        ScanEntity scan = scan(repository.getId(), null, "completed", SBOM, Instant.now().minusSeconds(60));
        finding(scan.getId(), "vulnerability", "critical", true);
        finding(scan.getId(), "vulnerability", "high", false);
        finding(scan.getId(), "secret", "high", false);

        JsonNode counts = attestation(scan.getId()).path("predicate").path("findings");

        assertThat(counts.path("kev").asLong()).isEqualTo(1);
        assertThat(counts.path("secrets").asLong()).isEqualTo(1);
        assertThat(counts.path("critical").asLong()).isEqualTo(1);
        assertThat(counts.path("high").asLong()).isEqualTo(2);
    }

    @Test
    @DisplayName("names a container by image and tag")
    void aContainer() throws Exception {
        ContainerEntity container = new ContainerEntity();
        container.setImageName("registry.example.invalid/shop");
        container.setTag("1.4.2");
        container = containers.save(container);
        ScanEntity scan = scan(null, container.getId(), "completed", SBOM, Instant.now().minusSeconds(60));

        JsonNode invocation = attestation(scan.getId()).path("predicate").path("invocation");

        assertThat(invocation.path("targetName").asText()).isEqualTo("registry.example.invalid/shop:1.4.2");
        assertThat(invocation.path("targetKind").asText()).isEqualTo("container");
    }

    @Test
    @DisplayName("refuses a scan that did not complete, or left no SBOM, rather than inventing a subject")
    void refusals() throws Exception {
        ScanEntity failed = scan(repository.getId(), null, "failed", SBOM, Instant.now());
        ScanEntity noSbom = scan(repository.getId(), null, "completed", null, Instant.now());

        mvc.perform(authenticated(get("/api/v1/attestations/scans/" + failed.getId()), admin))
                .andExpect(status().isConflict());
        mvc.perform(authenticated(get("/api/v1/attestations/scans/" + noSbom.getId()), admin))
                .andExpect(status().isConflict());
    }

    private JsonNode attestation(long scanId) throws Exception {
        String body = mvc.perform(authenticated(get("/api/v1/attestations/scans/" + scanId), admin))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        return JSON.readTree(body);
    }

    private ScanEntity scan(Long repoId, Long containerId, String status, String sbom, Instant createdAt) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setContainerId(containerId);
        scan.setStatus(status);
        scan.setBranch(repoId != null ? "main" : "n/a");
        scan.setCreatedAt(createdAt);
        scan.setSbom(sbom);
        return scans.save(scan);
    }

    private void verdict(Long repoId, Long containerId, boolean passed, Instant decidedAt, String source, Long version) {
        GateVerdictEntity verdict = new GateVerdictEntity();
        verdict.setId(UUID.randomUUID());
        verdict.setRepoId(repoId);
        verdict.setContainerId(containerId);
        verdict.setPassed(passed);
        verdict.setEvaluated(10);
        verdict.setViolations(passed ? 0 : 3);
        verdict.setPolicySource(source);
        verdict.setPolicyVersion(version);
        verdict.setDecidedAt(decidedAt);
        verdicts.save(verdict);
    }

    private void finding(long scanId, String type, String severity, boolean kev) {
        FindingEntity finding = new FindingEntity();
        finding.setScanId(scanId);
        finding.setType(type);
        finding.setSeverity(severity);
        finding.setSource("test");
        finding.setIsKev(kev);
        finding.setCreatedAt(Instant.now());
        findings.save(finding);
    }
}
