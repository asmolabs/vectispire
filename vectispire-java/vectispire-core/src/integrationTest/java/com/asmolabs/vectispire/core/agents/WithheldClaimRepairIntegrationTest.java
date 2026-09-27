package com.asmolabs.vectispire.core.agents;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.agents.AgentKind;
import com.asmolabs.vectispire.common.domain.agents.CredentialsMode;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.agents.internal.WithheldClaimRepair;
import com.asmolabs.vectispire.core.agents.persistence.AgentEntity;
import com.asmolabs.vectispire.core.agents.persistence.AgentRepository;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.targets.persistence.SshKeyEntity;
import com.asmolabs.vectispire.core.targets.persistence.SshKeyRepository;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * The one-shot repair of the attempts withheld claims counted, on each engine.
 *
 * <p>On an engine rather than in the HTTP suite because it is a data repair: the statements that
 * choose and reset the rows are what has to agree with the schema, and a repair that touched one
 * scan too many would destroy the only count that stops a jamming target — so each kind of scan it
 * must leave alone is here beside the one it repairs.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("giving back the attempts of withheld claims")
class WithheldClaimRepairIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final Optional<JdbcDatabaseContainer<?>> CONTAINER = ENGINE.container();

    @BeforeAll
    static void start() {
        CONTAINER.ifPresent(JdbcDatabaseContainer::start);
    }

    @AfterAll
    static void stop() {
        CONTAINER.ifPresent(JdbcDatabaseContainer::stop);
    }

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        Engine.configure(ENGINE, CONTAINER, registry);
    }

    @Autowired
    private WithheldClaimRepair repair;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private AgentRepository agents;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private ContainerRepository containers;

    @Autowired
    private SshKeyRepository sshKeys;

    @Autowired
    private AuditLogService audit;

    @Autowired
    private JdbcTemplate jdbc;

    private long keyed;
    private long open;

    @BeforeEach
    void emptyTables() {
        scans.deleteAll();
        agents.deleteAll();
        repositories.deleteAll();
        containers.deleteAll();
        sshKeys.deleteAll();
        // The application ran the repair at its start, on an empty database: forgetting that it did is
        // the only way to run it again. The trail is append-only for the application, not for a test.
        jdbc.update("delete from t_audit_log");

        SshKeyEntity key = new SshKeyEntity();
        key.setId(UUID.randomUUID());
        key.setName("deploy");
        key.setPrivateKey("v2:not-read-by-this-test");
        key.setCreatedAt(Instant.now());
        sshKeys.save(key);
        keyed = repository("keyed", key.getId());
        open = repository("open", null);
    }

    @Test
    @DisplayName("a waiting scan whose credential never left gets its attempts back; nothing else is touched")
    void onlyTheUndeliveredWaitingScans() {
        agent(CredentialsMode.DELEGATED);
        long inflated = scan(keyed, null, ScanStatus.PENDING, 7);
        long delivered = scan(keyed, null, ScanStatus.PENDING, 2);
        audit.record(AuditLogService.Record.of(
                AuditOperation.AGENT_CREDENTIAL_SENT, String.valueOf(delivered), "Deployment key delegated.", "edge"));
        long withoutCredential = scan(open, null, ScanStatus.PENDING, 2);
        long running = scan(keyed, null, ScanStatus.SCANNING, 1);
        long exhausted = scan(keyed, null, ScanStatus.FAILED, 3);
        long image = scan(null, container(), ScanStatus.PENDING, 1);
        long fresh = scan(keyed, null, ScanStatus.PENDING, 0);

        assertThat(repair.repairOnce()).isEqualTo(new WithheldClaimRepair.Outcome.Repaired(List.of(inflated)));

        assertThat(attempts(inflated)).isZero();
        // A real delivery happened: its count mixes real attempts with withheld ones, and cannot be split.
        assertThat(attempts(delivered)).isEqualTo(2);
        // Never withheld: no credential to withhold.
        assertThat(attempts(withoutCredential)).isEqualTo(2);
        assertThat(attempts(running)).isEqualTo(1);
        // Failed for good stays failed: running it again is the operator's decision.
        assertThat(attempts(exhausted)).isEqualTo(3);
        assertThat(scans.findById(exhausted).orElseThrow().getStatus()).isEqualTo(ScanStatus.FAILED.wireName());
        assertThat(attempts(image)).isEqualTo(1);
        assertThat(attempts(fresh)).isZero();

        assertThat(entries()).singleElement().asString().contains("1 waiting scan(s)").contains(String.valueOf(inflated));
    }

    @Test
    @DisplayName("once per database: a later start gives back nothing, even attempts counted since")
    void once() {
        agent(CredentialsMode.DELEGATED);
        long scan = scan(keyed, null, ScanStatus.PENDING, 4);
        repair.repairOnce();
        assertThat(attempts(scan)).isZero();

        // Counted since the upgrade, by a real takeover: a restart must not give it back.
        jdbc.update("update t_scan set attempts = 2 where id = ?", scan);

        assertThat(repair.repairOnce()).isEqualTo(new WithheldClaimRepair.Outcome.AlreadyDone());
        assertThat(attempts(scan)).isEqualTo(2);
        assertThat(entries()).hasSize(1);
    }

    @Test
    @DisplayName("a database with no delegated agent never reached the withheld path, and is only checked")
    void noDelegatedAgentNoRepair() {
        agent(CredentialsMode.LOCAL);
        long scan = scan(keyed, null, ScanStatus.PENDING, 2);

        assertThat(repair.repairOnce()).isEqualTo(new WithheldClaimRepair.Outcome.Repaired(List.of()));

        // A local agent or the built-in worker that died mid-scan: a real attempt, left as it is.
        assertThat(attempts(scan)).isEqualTo(2);
        assertThat(entries()).singleElement().asString().startsWith("Upgrade check");
        assertThat(repair.repairOnce()).isEqualTo(new WithheldClaimRepair.Outcome.AlreadyDone());
    }

    private List<String> entries() {
        return jdbc.queryForList("select description from t_audit_log where operation_type = ?", String.class,
                AuditOperation.SCAN_ATTEMPTS_REPAIRED.name());
    }

    private int attempts(long scan) {
        return scans.findById(scan).orElseThrow().getAttempts();
    }

    private void agent(CredentialsMode mode) {
        AgentEntity agent = new AgentEntity();
        agent.setName("agent-" + UUID.randomUUID());
        agent.setKind(AgentKind.REMOTE.wireName());
        agent.setCredentialsMode(mode.wireName());
        agent.setEnabled(true);
        agent.setCreatedAt(Instant.now());
        agents.save(agent);
    }

    private long repository(String name, UUID sshKeyId) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/" + name + ".git");
        repository.setName(name);
        repository.setBranch("main");
        repository.setSshKeyId(sshKeyId);
        return repositories.save(repository).getId();
    }

    private long container() {
        ContainerEntity image = new ContainerEntity();
        image.setImageName("team/service-" + System.nanoTime());
        image.setTag("1.0");
        return containers.save(image).getId();
    }

    private long scan(Long repoId, Long containerId, ScanStatus status, int attempts) {
        ScanEntity scan = new ScanEntity();
        scan.setRepoId(repoId);
        scan.setContainerId(containerId);
        scan.setBranch("main");
        scan.setStatus(status.wireName());
        scan.setCreatedAt(Instant.now());
        scan.setAttempts(attempts);
        if (status == ScanStatus.SCANNING) {
            scan.setClaimedBy("worker");
            scan.setClaimedAt(Instant.now());
            scan.setLeaseExpiresAt(Instant.now().plusSeconds(600));
        }
        return scans.save(scan).getId();
    }
}
