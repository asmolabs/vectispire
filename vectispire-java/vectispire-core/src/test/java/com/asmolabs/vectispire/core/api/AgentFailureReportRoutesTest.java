package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.crypto.ResultAttestation;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.fasterxml.jackson.databind.JsonNode;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * "I could not run this scan", through the real stack.
 *
 * <p>The lot that found it: an agent failing a clone dropped the scan, its lease took twenty minutes
 * to lapse, the reclaim spent an attempt, and the scans screen never showed why. Each test here
 * holds one half of what the report replaced that with — the owner, the attestation, the attempts,
 * the reason on the scan, and a report that applies once.
 */
@DisplayName("an agent's report that it could not run a scan")
class AgentFailureReportRoutesTest extends ApiTestBase {

    @Autowired
    private ScanRepository scans;

    @Autowired
    private ContainerRepository containers;

    @Autowired
    private AuditLogRepository auditEntries;

    private record Enrolled(String id, String token) {}

    private Enrolled declareAgent() throws Exception {
        String body = mvc.perform(authenticated(post("/api/v1/admin/agents"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"scanner-" + System.nanoTime() + "\", \"max_concurrent\": 4}"))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        JsonNode answer = json.readTree(body);
        return new Enrolled(answer.path("id").asText(), answer.path("secret").asText());
    }

    private String pinGeneratedKey(Enrolled agent) throws Exception {
        String body = mvc.perform(authenticated(put("/api/v1/admin/agents/" + agent.id() + "/signing-key"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"public_key\":\"generate\"}"))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        return json.readTree(body).path("privateKey").asText();
    }

    /** The claim's answer: the scan and the attempt it is. */
    private JsonNode claim(Enrolled agent) throws Exception {
        MvcResult started = mvc.perform(get("/api/v1/agent/jobs?wait=0").header("Authorization", "Bearer " + agent.token()))
                .andReturn();
        String body = mvc.perform(asyncDispatch(started)).andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return json.readTree(body);
    }

    /** A report as an agent older than the {@code kind} field sends it. */
    private static String report(int attempt, String reason) {
        return "{\"attempt\":" + attempt + ",\"reason\":\"" + reason + "\"}";
    }

    private static String report(int attempt, String reason, String kind) {
        return "{\"attempt\":" + attempt + ",\"reason\":\"" + reason + "\",\"kind\":\"" + kind + "\"}";
    }

    /** Whether the agent's poll comes back empty. */
    private boolean pollsNothing(Enrolled agent) throws Exception {
        MvcResult started = mvc.perform(get("/api/v1/agent/jobs?wait=0").header("Authorization", "Bearer " + agent.token()))
                .andReturn();
        return mvc.perform(asyncDispatch(started)).andReturn().getResponse().getStatus() == 204;
    }

    /** The wait a failure earned, served: what a minute — or five — passing does to the row. */
    private void waitServed(long scanId) {
        ScanEntity scan = scans.findById(scanId).orElseThrow();
        scan.setNotBefore(Instant.now().minusSeconds(1));
        scans.save(scan);
    }

    private ResultActions send(Enrolled agent, long scanId, String body, String signature) throws Exception {
        MockHttpServletRequestBuilder request = post("/api/v1/agent/jobs/" + scanId + "/failure")
                .header("Authorization", "Bearer " + agent.token())
                .contentType(MediaType.APPLICATION_JSON)
                .content(body);
        return mvc.perform(signature == null ? request : request.header(ResultAttestation.HEADER, signature));
    }

    @Test
    @DisplayName("requeues with the attempt counted and the reason shown, applies once, and fails for good at the last")
    void theLapsesRuleAtOnce() throws Exception {
        Enrolled agent = declareAgent();
        long scanId = pending();

        JsonNode first = claim(agent);
        assertThat(first.path("scanId").asLong()).isEqualTo(scanId);
        assertThat(first.path("attempt").asInt()).isEqualTo(1);

        Instant reported = Instant.now();
        send(agent, scanId, report(1, "The clone of ssh://git@gitea/team/app.git timed out."), null)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.retried").value(true))
                .andExpect(jsonPath("$.permanent").value(false))
                .andExpect(jsonPath("$.attempt").value(1))
                .andExpect(jsonPath("$.maxAttempts").value(3))
                .andExpect(jsonPath("$.retryAt").isNotEmpty());
        ScanEntity requeued = scans.findById(scanId).orElseThrow();
        assertThat(requeued.getStatus()).isEqualTo(ScanStatus.PENDING.wireName());
        assertThat(requeued.getClaimedBy()).isNull();
        assertThat(requeued.getLeaseExpiresAt()).isNull();
        assertThat(requeued.getAttempts()).isEqualTo(1);
        // A report with no kind — an agent older than the field — is transient: a minute's wait.
        assertThat(requeued.getNotBefore())
                .isBetween(reported.plusSeconds(55), Instant.now().plusSeconds(65));

        // **The defect this closes**: alone in its pool, the agent took the scan back at its next
        // poll, and three attempts went in seconds.
        assertThat(pollsNothing(agent)).as("the scan waits out its minute").isTrue();

        // What the scans screen reads: the reason, on the scan, while it waits for its next attempt.
        mvc.perform(authenticated(get("/api/v1/scans/" + scanId), asAdmin()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scan.status").value("pending"))
                .andExpect(jsonPath("$.scan.error").value(org.hamcrest.Matchers.allOf(
                        org.hamcrest.Matchers.containsString("Attempt 1 of 3"),
                        org.hamcrest.Matchers.containsString("back in the queue"),
                        org.hamcrest.Matchers.containsString("The clone of ssh://git@gitea/team/app.git timed out."))))
                .andExpect(jsonPath("$.scan.notBefore").value(requeued.getNotBefore().toString()));

        // The same report again — a retry on the way, a proxy's replay — does nothing.
        send(agent, scanId, report(1, "again"), null).andExpect(status().isConflict());
        assertThat(scans.findById(scanId).orElseThrow().getError()).doesNotContain("again");

        // Taken again by the same agent once the wait is served: the old report still does nothing
        // to the new attempt.
        waitServed(scanId);
        assertThat(claim(agent).path("attempt").asInt()).isEqualTo(2);
        assertThat(scans.findById(scanId).orElseThrow().getNotBefore()).as("a running scan waits for nothing").isNull();
        send(agent, scanId, report(1, "late"), null).andExpect(status().isConflict());
        assertThat(scans.findById(scanId).orElseThrow().getStatus()).isEqualTo(ScanStatus.SCANNING.wireName());

        Instant second = Instant.now();
        send(agent, scanId, report(2, "connection reset", "transient"), null).andExpect(jsonPath("$.retried").value(true));
        assertThat(scans.findById(scanId).orElseThrow().getNotBefore())
                .as("five minutes after the second attempt")
                .isBetween(second.plusSeconds(295), Instant.now().plusSeconds(305));
        waitServed(scanId);
        assertThat(claim(agent).path("attempt").asInt()).isEqualTo(3);
        send(agent, scanId, report(3, "connection reset", "transient"), null)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.retried").value(false))
                .andExpect(jsonPath("$.permanent").value(false))
                .andExpect(jsonPath("$.retryAt").doesNotExist());

        ScanEntity failed = scans.findById(scanId).orElseThrow();
        assertThat(failed.getStatus()).isEqualTo(ScanStatus.FAILED.wireName());
        assertThat(failed.getError()).contains("Attempt 3 of 3").contains("the last").contains("connection reset");
        assertThat(failed.getNotBefore()).isNull();
        assertThat(auditEntries.findAll())
                .filteredOn(entry -> AuditOperation.AGENT_SCAN_FAILED.wireName().equals(entry.getOperationType()))
                .hasSize(3);
    }

    @Test
    @DisplayName("a permanent failure fails the scan on its first attempt, with the reason, and is audited as such")
    void aPermanentFailureFailsAtOnce() throws Exception {
        Enrolled agent = declareAgent();
        long scanId = pending();
        claim(agent);

        send(agent, scanId, report(1, "The host key of ssh://git@gitea/team/app.git has changed.", "permanent"), null)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.retried").value(false))
                .andExpect(jsonPath("$.permanent").value(true))
                .andExpect(jsonPath("$.attempt").value(1))
                .andExpect(jsonPath("$.retryAt").doesNotExist());

        ScanEntity failed = scans.findById(scanId).orElseThrow();
        assertThat(failed.getStatus()).isEqualTo(ScanStatus.FAILED.wireName());
        assertThat(failed.getAttempts()).isEqualTo(1);
        assertThat(failed.getNotBefore()).isNull();
        assertThat(failed.getError())
                .contains("Attempt 1 of 3")
                .contains("another attempt would meet the same refusal")
                .contains("has changed");
        assertThat(pollsNothing(agent)).isTrue();
        assertThat(auditEntries.findAll())
                .filteredOn(entry -> AuditOperation.AGENT_SCAN_FAILED.wireName().equals(entry.getOperationType()))
                .filteredOn(entry -> entry.getDescription().contains("a permanent failure"))
                .hasSize(1);
    }

    @Test
    @DisplayName("a kind this version cannot read is transient, never a reason to fail for good")
    void anUnknownKindRetries() throws Exception {
        Enrolled agent = declareAgent();
        long scanId = pending();
        claim(agent);

        send(agent, scanId, report(1, "whatever", "catastrophic"), null)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.retried").value(true))
                .andExpect(jsonPath("$.permanent").value(false));
        assertThat(scans.findById(scanId).orElseThrow().getStatus()).isEqualTo(ScanStatus.PENDING.wireName());
    }

    @Test
    @DisplayName("is refused from an agent that does not hold the lease, and changes nothing")
    void onlyTheOwner() throws Exception {
        Enrolled owner = declareAgent();
        Enrolled other = declareAgent();
        long scanId = pending();
        claim(owner);

        send(other, scanId, report(1, "not mine"), null).andExpect(status().isConflict());

        ScanEntity scan = scans.findById(scanId).orElseThrow();
        assertThat(scan.getStatus()).isEqualTo(ScanStatus.SCANNING.wireName());
        assertThat(scan.getClaimedBy()).isEqualTo(owner.id());
        assertThat(scan.getError()).isNull();
    }

    /**
     * The threat the signature closes: a stolen API key posting reports would spend every attempt of
     * every scan it can claim, and keep those targets from ever being scanned.
     */
    @Test
    @DisplayName("from an agent whose key is pinned, only signed — as a failure, not as a result — and a refusal is audited")
    void signedLikeAResult() throws Exception {
        Enrolled agent = declareAgent();
        String privateKey = pinGeneratedKey(agent);
        long scanId = pending();
        claim(agent);
        String body = report(1, "clone refused");
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);

        send(agent, scanId, body, null).andExpect(status().isForbidden());
        send(agent, scanId, body, ResultAttestation.sign(privateKey, scanId, bytes)).andExpect(status().isForbidden());
        send(agent, scanId, body, ResultAttestation.signFailure(ResultAttestation.generate().privateKey(), scanId, bytes))
                .andExpect(status().isForbidden());
        assertThat(scans.findById(scanId).orElseThrow().getStatus()).isEqualTo(ScanStatus.SCANNING.wireName());
        assertThat(auditEntries.findAll())
                .filteredOn(entry -> AuditOperation.AGENT_RESULT_REFUSED.wireName().equals(entry.getOperationType()))
                .isNotEmpty();

        send(agent, scanId, body, ResultAttestation.signFailure(privateKey, scanId, bytes))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.retried").value(true));
    }

    @Test
    @DisplayName("a report that names no attempt is a 400, and the reason is stored scrubbed and on one line")
    void readAndScrubbed() throws Exception {
        Enrolled agent = declareAgent();
        long scanId = pending();
        claim(agent);

        send(agent, scanId, "{\"reason\":\"clone refused\"}", null).andExpect(status().isBadRequest());
        send(agent, scanId, "not json", null).andExpect(status().isBadRequest());

        send(agent, scanId, report(1, "https://oauth2:glpat-SECRET1234@gitlab.example/g/p.git\\nforged line"), null)
                .andExpect(status().isOk());
        assertThat(scans.findById(scanId).orElseThrow().getError())
                .doesNotContain("glpat-SECRET1234")
                .doesNotContain("\n")
                .contains("https://***@gitlab.example/g/p.git forged line");
    }

    /**
     * The statement's own condition, beside the read that precedes it: between the two, the lease can
     * lapse and the same agent take the scan again. Asked of the statement directly, since no sequence
     * of requests on one thread reaches that window.
     */
    @Test
    @DisplayName("the release repeats the owner and the attempt, so a report read before a retake changes nothing")
    void theStatementRepeatsTheCondition() throws Exception {
        Enrolled agent = declareAgent();
        long scanId = pending();
        claim(agent);
        String running = ScanStatus.SCANNING.wireName();
        String pending = ScanStatus.PENDING.wireName();

        assertThat(scans.releaseOwnedAttempt(scanId, running, agent.id(), 2, pending, "stale", null)).isZero();
        assertThat(scans.releaseOwnedAttempt(scanId, running, "somebody-else", 1, pending, "stale", null)).isZero();
        assertThat(scans.findById(scanId).orElseThrow().getStatus()).isEqualTo(running);

        assertThat(scans.releaseOwnedAttempt(scanId, running, agent.id(), 1, pending, "applied", null)).isEqualTo(1);
    }

    /** An image scan: its task needs a container row and nothing else — no key, no clone. */
    private long pending() {
        ContainerEntity image = new ContainerEntity();
        image.setImageName("team/service-" + System.nanoTime());
        image.setTag("1.0");
        long containerId = containers.save(image).getId();

        ScanEntity scan = new ScanEntity();
        scan.setContainerId(containerId);
        scan.setBranch("");
        scan.setStatus(ScanStatus.PENDING.wireName());
        scan.setCreatedAt(Instant.now());
        scan.setFindingsCount(0);
        scan.setNewIssuesCount(0);
        scan.setResolvedIssuesCount(0);
        scan.setAttempts(0);
        return scans.save(scan).getId();
    }
}
