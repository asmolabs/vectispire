package com.asmolabs.vectispire.core.agents;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.agents.AgentKind;
import com.asmolabs.vectispire.common.domain.agents.CredentialsMode;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.agents.internal.WithheldClaimRepair;
import com.asmolabs.vectispire.core.agents.persistence.AgentEntity;
import com.asmolabs.vectispire.core.agents.persistence.AgentRepository;
import com.asmolabs.vectispire.core.audit.AuditLogQueryService;
import com.asmolabs.vectispire.core.audit.AuditLogService;
import com.asmolabs.vectispire.core.maintenance.OneShotJobs;
import com.asmolabs.vectispire.core.maintenance.persistence.OneShotJobRepository;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.targets.TargetCatalog;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.ContainerEntity;
import com.asmolabs.vectispire.core.targets.persistence.ContainerRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import com.asmolabs.vectispire.core.targets.persistence.SshKeyEntity;
import com.asmolabs.vectispire.core.targets.persistence.SshKeyRepository;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.CannotAcquireLockException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
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
    private static final JdbcDatabaseContainer<?> CONTAINER = ENGINE.container();

    @BeforeAll
    static void start() {
        CONTAINER.start();
    }

    @AfterAll
    static void stop() {
        CONTAINER.stop();
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

    @Autowired
    private OneShotJobRepository oneShotJobs;

    @Autowired
    private OneShotJobs once;

    @Autowired
    private ScanCatalog scanCatalog;

    @Autowired
    private TargetCatalog targetCatalog;

    @Autowired
    private AuditLogQueryService trail;

    @Autowired
    private PlatformTransactionManager transactions;

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
        jdbc.update("delete from t_one_shot_job");

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

    /**
     * The wait a failed attempt earns grows with the attempts counted: a scan given its count back and
     * still held for the wait of its "third" attempt would be held back for failures no longer counted.
     */
    @Test
    @DisplayName("the attempts given back take their retry wait with them, and a scan not repaired keeps its own")
    void theWaitGoesWithTheAttempts() {
        agent(CredentialsMode.DELEGATED);
        long inflated = scan(keyed, null, ScanStatus.PENDING, 2);
        long delivered = scan(keyed, null, ScanStatus.PENDING, 2);
        audit.record(AuditLogService.Record.of(
                AuditOperation.AGENT_CREDENTIAL_SENT, String.valueOf(delivered), "Deployment key delegated.", "edge"));
        Instant later = Instant.now().plusSeconds(300);
        for (long id : new long[] {inflated, delivered}) {
            ScanEntity waiting = scans.findById(id).orElseThrow();
            waiting.setNotBefore(later);
            scans.save(waiting);
        }

        repair.repairOnce();

        assertThat(scans.findById(inflated).orElseThrow().getNotBefore()).isNull();
        assertThat(scans.findById(delivered).orElseThrow().getNotBefore()).isNotNull();
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

    /**
     * Two instances starting together, forced into the interleaving that wrote two entries: the second
     * reads the trail while the first is between its claim and its commit, so neither has written its
     * entry yet and both pass the only check there used to be. Latches, not luck — left to timing,
     * the first finishes before the second starts and the test proves nothing. And the first records
     * while the second's refused transaction is still open, the interleaving that lost the entry on
     * CI's SQLite fixture, as it then was, and that timing alone produced there one run in a few.
     */
    @Test
    @DisplayName("two instances starting together: one runs it and writes the entry, the other writes nothing")
    void twoInstancesAtOnce() throws Exception {
        agent(CredentialsMode.DELEGATED);
        long inflated = scan(keyed, null, ScanStatus.PENDING, 5);

        CountDownLatch firstClaimed = new CountDownLatch(1);
        CountDownLatch secondClaiming = new CountDownLatch(1);
        CountDownLatch secondRefused = new CountDownLatch(1);
        CountDownLatch firstDone = new CountDownLatch(1);
        // The first instance pauses right after its claim, before its work and its commit; and once
        // committed, it records its entry only when the second has been refused and still holds its
        // transaction open. That is the moment CI hit on the SQLite fixture of the time: the refused
        // insert kept the file's write lock until its rollback, the entry's transaction had already
        // read the chain's head, and SQLite answered that upgrade SQLITE_BUSY at once — the repair
        // ran and its entry was lost, logged and swallowed. The engines wait or pick a victim there,
        // and the entry is tried again either way.
        AgentRepository pausing = (AgentRepository) Proxy.newProxyInstance(
                AgentRepository.class.getClassLoader(), new Class<?>[] {AgentRepository.class},
                (proxy, method, args) -> {
                    if (method.getName().equals("findAll") && method.getParameterCount() == 0) {
                        firstClaimed.countDown();
                        assertThat(secondClaiming.await(30, TimeUnit.SECONDS)).isTrue();
                        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                            @Override
                            public void afterCommit() {
                                try {
                                    assertThat(secondRefused.await(30, TimeUnit.SECONDS)).isTrue();
                                } catch (InterruptedException interrupted) {
                                    Thread.currentThread().interrupt();
                                }
                            }
                        });
                    }
                    try {
                        return method.invoke(agents, args);
                    } catch (InvocationTargetException thrown) {
                        throw thrown.getCause();
                    }
                });
        // The second says when it has read the trail — found no entry — and reaches for the claim.
        OneShotJobs signalling = new OneShotJobs(oneShotJobs, Clock.systemUTC()) {
            @Override
            public void claim(String name) {
                secondClaiming.countDown();
                try {
                    super.claim(name);
                } finally {
                    // Still inside the refused transaction: held, not waited on for ever, since an
                    // entry written by trying again needs the lock back.
                    secondRefused.countDown();
                    try {
                        firstDone.await(500, TimeUnit.MILLISECONDS);
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                    }
                }
            }
        };
        WithheldClaimRepair first = new WithheldClaimRepair(
                pausing, scanCatalog, targetCatalog, trail, audit, this.once, transactions);
        WithheldClaimRepair second = new WithheldClaimRepair(
                agents, scanCatalog, targetCatalog, trail, audit, signalling, transactions);

        try (ExecutorService starts = Executors.newFixedThreadPool(2)) {
            Future<WithheldClaimRepair.Outcome> one = starts.submit(() -> {
                try {
                    return first.repairOnce();
                } finally {
                    firstDone.countDown();
                }
            });
            assertThat(firstClaimed.await(30, TimeUnit.SECONDS)).isTrue();
            Future<WithheldClaimRepair.Outcome> other = starts.submit(second::repairOnce);

            assertThat(List.of(one.get(60, TimeUnit.SECONDS), other.get(60, TimeUnit.SECONDS)))
                    .containsExactly(
                            new WithheldClaimRepair.Outcome.Repaired(List.of(inflated)),
                            new WithheldClaimRepair.Outcome.ClaimedElsewhere());
        }
        assertThat(attempts(inflated)).isZero();
        assertThat(entries()).singleElement().asString().contains("1 waiting scan(s)");
    }

    @Test
    @DisplayName("a repair that fails half-way is not recorded as run: the next start does it")
    void aFailedRunIsNotARun() {
        agent(CredentialsMode.DELEGATED);
        long inflated = scan(keyed, null, ScanStatus.PENDING, 3);
        AgentRepository failing = (AgentRepository) Proxy.newProxyInstance(
                AgentRepository.class.getClassLoader(), new Class<?>[] {AgentRepository.class},
                (proxy, method, args) -> {
                    throw new IllegalStateException("the database went away mid-repair");
                });
        WithheldClaimRepair broken = new WithheldClaimRepair(
                failing, scanCatalog, targetCatalog, trail, audit, once, transactions);

        broken.onApplicationReady();

        assertThat(jdbc.queryForObject("select count(*) from t_one_shot_job", Integer.class))
                .as("the claim rolled back with the work it was taken for")
                .isZero();
        assertThat(repair.repairOnce()).isEqualTo(new WithheldClaimRepair.Outcome.Repaired(List.of(inflated)));
    }

    @Test
    @DisplayName("a claim that failed with nobody holding the job is a failure, not another instance's run")
    void aFailedClaimIsNotALostOne() {
        agent(CredentialsMode.DELEGATED);
        long inflated = scan(keyed, null, ScanStatus.PENDING, 3);
        OneShotJobs failing = new OneShotJobs(oneShotJobs, Clock.systemUTC()) {
            @Override
            public void claim(String name) {
                throw new CannotAcquireLockException("the lock wait timed out");
            }
        };
        WithheldClaimRepair unlucky = new WithheldClaimRepair(
                agents, scanCatalog, targetCatalog, trail, audit, failing, transactions);

        assertThatThrownBy(unlucky::repairOnce).isInstanceOf(CannotAcquireLockException.class);

        assertThat(entries()).isEmpty();
        assertThat(repair.repairOnce()).isEqualTo(new WithheldClaimRepair.Outcome.Repaired(List.of(inflated)));
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
