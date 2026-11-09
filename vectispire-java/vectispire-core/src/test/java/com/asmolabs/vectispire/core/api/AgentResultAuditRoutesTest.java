package com.asmolabs.vectispire.core.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.asyncDispatch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.agents.internal.AgentResultAuditDelivery;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.maintenance.internal.MaintenanceJobs;
import com.asmolabs.vectispire.core.outbox.persistence.OutboxMessageEntity;
import com.asmolabs.vectispire.core.outbox.persistence.OutboxMessageRepository;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

/**
 * The audit entry of an agent's accepted result is queued with the result and written from the outbox
 * (decision 0033, lot 4).
 *
 * <p>It was written after the result's commit, and a stop in between lost it for good: a re-sent
 * result is answered {@code NoLongerYours}, so nothing wrote it again. It could not simply move inside
 * the result's transaction either, which would have held the audit chain's lock for as long as the
 * scan took to write. What is asserted is the shape that replaces both: nothing in the log until the
 * relay, a message that commits with the result, and the entry the relay writes from it.
 */
@DisplayName("an agent's accepted result is audited from the outbox")
class AgentResultAuditRoutesTest extends ApiTestBase {

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private AuditLogRepository auditLog;

    @Autowired
    private OutboxMessageRepository outbox;

    @Autowired
    private MaintenanceJobs jobs;

    @Autowired
    private org.springframework.jdbc.core.JdbcTemplate jdbc;

    private String agentName;
    private String agent;
    private long scanId;

    @BeforeEach
    void aClaimedScan() throws Exception {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/audited-" + System.nanoTime() + ".git");
        repository.setBranch("main");
        long repositoryId = repositories.save(repository).getId();

        ScanEntity pending = new ScanEntity();
        pending.setRepoId(repositoryId);
        pending.setBranch("main");
        pending.setStatus(ScanStatus.PENDING.wireName());
        pending.setCreatedAt(Instant.now());
        pending.setFindingsCount(0);
        pending.setNewIssuesCount(0);
        pending.setResolvedIssuesCount(0);
        pending.setAttempts(0);
        scans.save(pending);

        agentName = "agent-" + System.nanoTime();
        agent = json.readTree(mvc.perform(authenticated(post("/api/v1/admin/agents"), asAdmin())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\": \"" + agentName + "\", \"max_concurrent\": 1}"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString()).get("secret").asText();
        MvcResult started = mvc.perform(get("/api/v1/agent/jobs?wait=0").header("Authorization", "Bearer " + agent))
                .andReturn();
        scanId = json.readTree(mvc.perform(asyncDispatch(started)).andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString()).path("scanId").asLong();
    }

    @Test
    @DisplayName("the result is accepted and its entry queued with it; the relay writes the entry, dated in its description")
    void queuedThenWritten() throws Exception {
        Instant before = Instant.now();
        submit(scanId).andExpect(status().isOk());

        assertThat(entries()).as("nothing in the log until the relay").isEmpty();
        assertThat(queued()).as("queued in the result's transaction").singleElement();

        jobs.relayNotifications();

        assertThat(entries()).singleElement().satisfies(entry -> {
            assertThat(entry.getResourceId()).isEqualTo(String.valueOf(scanId));
            assertThat(entry.getUserId()).isEqualTo(agentName);
            assertThat(entry.getDescription())
                    .startsWith("Result accepted from agent \"" + agentName + "\" at ")
                    .contains("(not attested).")
                    .contains("Delivery " + queued().getFirst().getId());
            assertThat(entry.getTimestamp()).isAfterOrEqualTo(before.truncatedTo(java.time.temporal.ChronoUnit.MILLIS));
        });
        assertThat(queued()).singleElement().satisfies(message -> assertThat(message.getStatus()).isEqualTo("sent"));
    }

    @Test
    @DisplayName("an entry that cannot be written stays queued with its reason, for the relay to retry — not dropped as record() would")
    void aFailedWriteIsRetried() throws Exception {
        submit(scanId).andExpect(status().isOk());

        // The audit log refuses to write without the chain's lock row (V66): the one failure an entry
        // can be given here without a mock, and the one `record` would log and swallow.
        jdbc.update("delete from t_audit_chain_head");
        try {
            jobs.relayNotifications();
        } finally {
            jdbc.update("insert into t_audit_chain_head (id) values (1)");
        }

        assertThat(entries()).isEmpty();
        assertThat(queued()).singleElement().satisfies(message -> {
            assertThat(message.getStatus()).isEqualTo("pending");
            assertThat(message.getAttempts()).isEqualTo(1);
            assertThat(message.getLastError()).contains("t_audit_chain_head");
        });
    }

    @Test
    @DisplayName("a result that is not the agent's queues nothing and audits nothing")
    void aRefusedResultQueuesNothing() throws Exception {
        submit(scanId + 1_000).andExpect(status().isConflict());

        jobs.relayNotifications();

        assertThat(queued()).isEmpty();
        assertThat(entries()).isEmpty();
    }

    private org.springframework.test.web.servlet.ResultActions submit(long id) throws Exception {
        return mvc.perform(post("/api/v1/agent/jobs/" + id + "/result")
                .header("Authorization", "Bearer " + agent)
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"secrets\":[], \"duration\":\"PT1S\"}"));
    }

    private List<AuditLogEntity> entries() {
        return auditLog.findAll().stream()
                .filter(entry -> AuditOperation.AGENT_RESULT_SUBMITTED.wireName().equals(entry.getOperationType()))
                .toList();
    }

    private List<OutboxMessageEntity> queued() {
        return outbox.findAll().stream()
                .filter(message -> AgentResultAuditDelivery.TYPE.equals(message.getMessageType()))
                .toList();
    }
}
