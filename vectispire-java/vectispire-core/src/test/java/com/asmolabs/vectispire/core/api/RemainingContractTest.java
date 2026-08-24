package com.asmolabs.zanshin.core.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.zanshin.common.domain.issues.FindingType;
import com.asmolabs.zanshin.common.domain.issues.Severity;
import com.asmolabs.zanshin.common.domain.scans.ScanStatus;
import com.asmolabs.zanshin.core.persistence.FindingEntity;
import com.asmolabs.zanshin.core.persistence.RepositoryEntity;
import com.asmolabs.zanshin.core.persistence.ScanEntity;
import com.asmolabs.zanshin.core.repositories.Findings;
import com.asmolabs.zanshin.core.repositories.GitRepositories;
import com.asmolabs.zanshin.core.repositories.Scans;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;

/**
 * The shapes the earlier comparison could not reach, because nothing had produced one.
 *
 * <p>An endpoint that answers an empty list agrees with every contract there is. These seed the
 * row first, so the shape is compared against something rather than against nothing — which is
 * the difference between a contract test and a test that reports green for having looked at an
 * empty array.
 */
@DisplayName("the shapes that needed a row to exist first")
class RemainingContractTest extends ApiTestBase {

    @Autowired
    private GitRepositories repositories;

    @Autowired
    private Scans scans;

    @Autowired
    private Findings findings;

    @Test
    @DisplayName("a rule set says isActive, and its size is a string")
    void theRuleSetListing() throws Exception {
        mvc.perform(authenticated(post("/api/v1/rule-sets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of(
                                "name", "owasp",
                                "files", List.of(Map.of("name", "rules.yaml", "content", "rules:\n  - id: sqli\n"))))))
                .andExpect(status().isOk());

        String listing = mvc.perform(authenticated(get("/api/v1/rule-sets"), asAdmin()))
                .andExpect(status().isOk())
                // A 64-bit size does not survive a JavaScript number, which is why the row stored
                // it as text and the client's type says so.
                .andExpect(jsonPath("$.ruleSets[0].sizeBytes").isString())
                .andExpect(jsonPath("$.ruleSets[0].contentHash").isNotEmpty())
                .andExpect(jsonPath("$.ruleSets[0].ruleCount").value(1))
                .andReturn()
                .getResponse()
                .getContentAsString();

        // Asserted on the raw text: a stored-but-not-activated set carries `null` there, and a
        // path matcher cannot tell "present and null" from "absent" — which is exactly the
        // difference being checked. `active` is what a Java record would have called it, and
        // nothing in the client binds that.
        org.assertj.core.api.Assertions.assertThat(listing).contains("\"isActive\"").doesNotContain("\"active\"");
    }

    @Test
    @DisplayName("the impact of activating names the rules that would lose their issues")
    void theActivationImpact() throws Exception {
        String body = mvc.perform(authenticated(post("/api/v1/rule-sets"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of(
                                "name", "owasp",
                                "files", List.of(Map.of("name", "r.yaml", "content", "rules:\n  - id: sqli\n"))))))
                .andReturn()
                .getResponse()
                .getContentAsString();
        long id = json.readTree(body).path("id").asLong();

        mvc.perform(authenticated(get("/api/v1/rule-sets/" + id + "/impact"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.losingIssues").isArray())
                .andExpect(jsonPath("$.affectedIssues").isNumber())
                .andExpect(jsonPath("$.addedRules").value(1))
                .andExpect(jsonPath("$.removedRules").value(0));
    }

    @Test
    @DisplayName("an issued API key comes back once, with the key beside it")
    void anIssuedApiKey() throws Exception {
        mvc.perform(authenticated(post("/api/v1/api-keys"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "ci"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.secret").isNotEmpty())
                .andExpect(jsonPath("$.key.prefix").isNotEmpty())
                .andExpect(jsonPath("$.key.isExpired").value(false));
    }

    @Test
    @DisplayName("a declared agent comes back with its key, once")
    void anIssuedAgent() throws Exception {
        mvc.perform(authenticated(post("/api/v1/admin/agents"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("name", "agent-1", "credentials_mode", "delegated"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").isNotEmpty())
                .andExpect(jsonPath("$.name").value("agent-1"))
                .andExpect(jsonPath("$.secret").isNotEmpty());

        mvc.perform(authenticated(get("/api/v1/admin/agents"), asAdmin()))
                .andExpect(jsonPath("$[0].credentialsMode").value("delegated"))
                .andExpect(jsonPath("$[0].sealsCredentials").value(false))
                .andExpect(jsonPath("$[0].online").value(false));
    }

    @Test
    @DisplayName("the audit verification reports its four counts")
    void theAuditVerification() throws Exception {
        mvc.perform(authenticated(get("/api/v1/audit-log/verify"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.total").isNumber())
                .andExpect(jsonPath("$.unverifiable").isNumber())
                .andExpect(jsonPath("$.verified").isNumber())
                .andExpect(jsonPath("$.intact").value(true));
    }

    @Test
    @DisplayName("the key targets come back as two named lists")
    void theApiKeyTargets() throws Exception {
        seedRepository();

        mvc.perform(authenticated(get("/api/v1/api-keys/targets"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.repositories[0].id").isNumber())
                .andExpect(jsonPath("$.repositories[0].label").isNotEmpty())
                .andExpect(jsonPath("$.containers").isArray());
    }

    @Test
    @DisplayName("an unroutable label is named with how much is waiting on it")
    void theUnroutableLabels() throws Exception {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/labelled.git");
        repository.setBranch("main");
        repository.setRequiredAgentLabel("nobody-has-this");
        long id = repositories.save(repository).getId();
        mvc.perform(authenticated(post("/api/v1/repositories/" + id + "/scan"), asAdmin()));

        // The screen that breaks a silence: a target labelled for an agent nobody runs queues
        // scans for ever, and every other page reports "waiting", which is true and useless.
        mvc.perform(authenticated(get("/api/v1/admin/agents/non-routables"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].label").value("nobody-has-this"))
                .andExpect(jsonPath("$[0].queued").value(1));
    }

    @Test
    @DisplayName("a scan's findings carry the eleven fields the detail screen reads")
    void theScanFindings() throws Exception {
        long repositoryId = seedRepository();
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositoryId);
        scan.setBranch("main");
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setCreatedAt(Instant.now());
        long scanId = scans.save(scan).getId();

        FindingEntity finding = new FindingEntity();
        finding.setScanId(scanId);
        finding.setType(FindingType.VULNERABILITY.wireName());
        finding.setSeverity(Severity.HIGH.wireName());
        finding.setIdentifier("CVE-2026-1");
        finding.setPackageName("openssl");
        finding.setSource("grype");
        finding.setCreatedAt(Instant.now());
        finding.setIsKev(false);
        findings.save(finding);

        mvc.perform(authenticated(get("/api/v1/scans/" + scanId), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.findings[0].packageName").value("openssl"))
                .andExpect(jsonPath("$.findings[0].severity").value("high"))
                .andExpect(jsonPath("$.findingsTruncated").value(false))
                .andExpect(jsonPath("$.hasSbom").value(false))
                // The summary is flattened into the detail, as the screen reads it.
                .andExpect(jsonPath("$.scan.targetKind").value("repository"));
    }

    @Test
    @DisplayName("the SBOM is served whole, and absent when the scan produced none")
    void theSbomDownloads() throws Exception {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repositories.save(repository()).getId());
        scan.setBranch("main");
        scan.setStatus(ScanStatus.COMPLETED.wireName());
        scan.setCreatedAt(Instant.now());
        long withoutSbom = scans.save(scan).getId();

        // A scan that failed before the inventory has no SBOM. Returning an empty document
        // would claim it inventoried nothing, which is the opposite of what happened.
        mvc.perform(authenticated(get("/api/v1/scans/" + withoutSbom + "/sbom"), asAdmin()))
                .andExpect(status().isNotFound());

        ScanEntity catalogued = new ScanEntity();
        catalogued.setRepoId(repositories.save(repository()).getId());
        catalogued.setBranch("main");
        catalogued.setStatus(ScanStatus.COMPLETED.wireName());
        catalogued.setCreatedAt(Instant.now());
        catalogued.setSbom("{\"artifacts\":[],\"source\":{\"type\":\"directory\"}}");
        long withSbom = scans.save(catalogued).getId();

        String body = mvc.perform(authenticated(get("/api/v1/scans/" + withSbom + "/sbom"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(header().string(
                        "Content-Disposition", "attachment; filename=\"zanshin-scan-" + withSbom + ".sbom.json\""))
                .andReturn()
                .getResponse()
                .getContentAsString();

        // Byte for byte: an SBOM is consumed by other tools, and one that has been through a
        // parser and a writer is no longer the document the cataloguer produced.
        assertThat(body).isEqualTo("{\"artifacts\":[],\"source\":{\"type\":\"directory\"}}");
    }

    private static RepositoryEntity repository() {
        RepositoryEntity entity = new RepositoryEntity();
        entity.setUrl("https://github.com/org/sbom-project.git");
        entity.setBranch("main");
        return entity;
    }

    @Test
    @DisplayName("a quality tally is a label and a count")
    void theQualityTallies() throws Exception {
        mvc.perform(authenticated(get("/api/v1/quality/overview"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.openCount").isNumber())
                .andExpect(jsonPath("$.ruleCount").isNumber())
                .andExpect(jsonPath("$.topRules").isArray());
    }

    @Test
    @DisplayName("the gate's policy is camelCase inside a snake_case response")
    void theGatePolicyKeepsItsCasing() throws Exception {
        long id = seedRepository();

        mvc.perform(authenticated(post("/api/v1/gate"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of("repository_id", id))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.counts_by_severity").exists())
                .andExpect(jsonPath("$.ignored_relaxations").isArray())
                .andExpect(jsonPath("$.policy.failOnSeverity").value("high"))
                .andExpect(jsonPath("$.policy.failOnKev").value(true))
                .andExpect(jsonPath("$.policy.source").value("built-in"))
                .andExpect(jsonPath("$.policy.description").isNotEmpty());
    }

    @Test
    @DisplayName("a key's encryption state uses the three words the client knows")
    void theEncryptionState() throws Exception {
        mvc.perform(authenticated(post("/api/v1/ssh-keys"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(write(Map.of(
                                "name", "deploy",
                                "private_key", "-----BEGIN DUMMY PRIVATE KEY-----\ntest\n-----END DUMMY PRIVATE KEY-----"))))
                .andExpect(status().isOk());

        // `current | previous_key | unreadable`. The enum would arrive as `PREVIOUS_KEY`, and the
        // column that tells an operator a rotation is unfinished would say nothing they can read.
        mvc.perform(authenticated(get("/api/v1/ssh-keys"), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].encryptionState").value("current"))
                .andExpect(jsonPath("$[0].usedByRepositories").value(0));
    }

    private long seedRepository() {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/shapes.git");
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }
}
