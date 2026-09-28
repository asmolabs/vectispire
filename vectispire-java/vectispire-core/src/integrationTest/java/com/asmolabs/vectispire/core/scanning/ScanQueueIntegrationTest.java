package com.asmolabs.vectispire.core.scanning;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.agents.AgentKind;
import com.asmolabs.vectispire.common.domain.agents.CredentialsMode;
import com.asmolabs.vectispire.common.domain.scans.ScanStatus;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.agents.persistence.AgentEntity;
import com.asmolabs.vectispire.core.agents.persistence.AgentRepository;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.scanning.internal.ScanQueue;
import com.asmolabs.vectispire.core.scanning.persistence.ScanEntity;
import com.asmolabs.vectispire.core.scanning.persistence.ScanRepository;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * Claiming from the queue, against a real engine, from several threads at once.
 *
 * <p><b>This is the test the whole four-engine campaign exists for.</b> A claim that hands the
 * same scan to two workers is invisible in a unit test with a mock, invisible on a single
 * thread, and invisible on the one engine the developer happens to run. It shows up as two
 * agents cloning the same repository and reporting the same findings twice.
 *
 * <p>It also pins the property that is easy to lose while making the first one hold:
 * <b>everything queued must eventually be claimed</b>. A claim that never double-serves because
 * it serves almost nothing passes the first assertion and starves the queue.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("claiming from the scan queue")
class ScanQueueIntegrationTest {

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
    private ScanQueue queue;

    @Autowired
    private ScanRepository scans;

    @Autowired
    private TransactionTemplate transactions;

    @Autowired
    private AgentRepository agents;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private com.asmolabs.vectispire.core.targets.TargetCatalog targets;

    @Autowired
    private com.asmolabs.vectispire.core.targets.persistence.SshKeyRepository sshKeys;

    @BeforeEach
    void emptyQueue() {
        scans.deleteAll();
        agents.deleteAll();
        repositories.deleteAll();
        sshKeys.deleteAll();
    }

    /** A repository row, which a scan naming it needs: {@code repo_id} is a foreign key. */
    private long repository(String name) {
        RepositoryEntity repository = new RepositoryEntity();
        repository.setUrl("https://example.invalid/" + name + ".git");
        repository.setName(name);
        repository.setBranch("main");
        return repositories.save(repository).getId();
    }

    /** The exclusion of an agent kept from one repository, as the owner of the repositories answers it. */
    private static ScanQueue.Exclusion excluding(long repository) {
        return repositories -> repositories.contains(repository) ? Set.of(repository) : Set.of();
    }

    /** {@code count} scans of one repository, queued after everything already waiting. */
    private void enqueueFor(long repoId, int count, String requiredLabel) {
        Instant after = Instant.parse("2026-08-13T11:00:00Z").plusSeconds(scans.count());
        List<ScanEntity> pending = IntStream.range(0, count)
                .mapToObj(i -> {
                    ScanEntity scan = new ScanEntity();
                    scan.setRepoId(repoId);
                    scan.setBranch("main");
                    scan.setStatus(ScanStatus.PENDING.wireName());
                    scan.setCreatedAt(after.plusSeconds(i));
                    scan.setAttempts(0);
                    scan.setRequiredAgentLabel(requiredLabel);
                    return scan;
                })
                .toList();
        scans.saveAll(pending);
    }

    /** A remote agent's row: the claim takes it as its lock, so it has to exist. */
    private UUID agent(String name) {
        AgentEntity agent = new AgentEntity();
        agent.setName(name);
        agent.setKind(AgentKind.REMOTE.wireName());
        agent.setCredentialsMode(CredentialsMode.LOCAL.wireName());
        agent.setEnabled(true);
        agent.setCreatedAt(Instant.now());
        return agents.save(agent).getId();
    }

    private void enqueue(int count, String requiredLabel) {
        List<ScanEntity> pending = IntStream.range(0, count)
                .mapToObj(i -> {
                    ScanEntity scan = new ScanEntity();
                    scan.setBranch("main");
                    scan.setStatus(ScanStatus.PENDING.wireName());
                    scan.setCreatedAt(Instant.parse("2026-08-13T10:00:00Z").plusSeconds(i));
                    scan.setFindingsCount(0);
                    scan.setNewIssuesCount(0);
                    scan.setResolvedIssuesCount(0);
                    scan.setAttempts(0);
                    scan.setRequiredAgentLabel(requiredLabel);
                    return scan;
                })
                .toList();
        scans.saveAll(pending);
    }

    @Test
    @DisplayName("no scan is ever handed to two workers, and the queue still drains")
    void neverServesTheSameScanTwice() throws Exception {
        // Two agents cloning the same repository and reporting the same findings twice is what
        // the first assertion prevents. It cannot be seen on one thread, and it cannot be seen
        // with a mock.
        //
        // **Rounds, not one burst, and that is not the test being lenient.** Agents poll; a
        // round is a poll. One burst would also be a weaker test — it exercises the race once,
        // where this exercises it until the queue is empty. And on MySQL one burst genuinely
        // cannot drain it: skipped rows count against the `LIMIT` there, so a claimant whose
        // candidates are all locked comes back with nothing while rows remain. That is the
        // defect the retry loop exists for, and asserting "one burst serves everything" would
        // be asserting a property no engine owes us.
        enqueue(20, null);

        int workers = 8;
        List<Long> served = new ArrayList<>();

        try (ExecutorService pool = Executors.newFixedThreadPool(workers)) {
            for (int round = 0; round < 20 && served.size() < 20; round++) {
                List<Callable<List<Long>>> claims = IntStream.range(0, workers)
                        .mapToObj(worker -> (Callable<List<Long>>) () ->
                                queue.claim(5, "worker-" + worker, List.of()).stream()
                                        .map(ScanEntity::getId)
                                        .toList())
                        .toList();

                for (Future<List<Long>> claim : pool.invokeAll(claims)) {
                    served.addAll(claim.get());
                }
            }
        }

        assertThat(served).as("a scan served twice is a repository scanned twice").doesNotHaveDuplicates();
        // The property that is easy to lose while securing the first: a claim that never
        // double-serves because it serves almost nothing passes the assertion above and starves
        // the queue forever.
        assertThat(served).as("everything queued must eventually be claimed").hasSize(20);
        assertThat(scans.countByStatus(ScanStatus.PENDING.wireName())).isZero();
    }

    @Test
    @DisplayName("an agent only takes what it is entitled to, and the filter is inside the lock")
    void respectsTheRoutingLabel() {
        enqueue(3, "production");
        enqueue(2, null);

        // No label: only the unrouted work. An agent with no label does not match everything —
        // the reverse reading is the seductive one, and it makes the requirement inoperative at
        // the first agent registered without thinking about it.
        assertThat(queue.claim(10, "plain", List.of())).hasSize(2);
        assertThat(queue.claim(10, "prod", List.of("production"))).hasSize(3);
    }

    @Test
    @DisplayName("a claim marks what it took, in the same commit")
    void marksWhatItTook() {
        enqueue(2, null);

        List<ScanEntity> claimed = queue.claim(2, "worker", List.of());

        assertThat(claimed).allSatisfy(scan -> {
            assertThat(scan.getStatus()).isEqualTo(ScanStatus.SCANNING.wireName());
            assertThat(scan.getClaimedBy()).isEqualTo("worker");
            assertThat(scan.getLeaseExpiresAt()).isNotNull();
            assertThat(scan.getAttempts()).isEqualTo(1);
        });
        assertThat(scans.countByStatus(ScanStatus.PENDING.wireName())).isZero();
    }

    @Test
    @DisplayName("an empty queue costs one round, not twelve")
    void stopsEarlyOnAnEmptyQueue() {
        // The retry loop exists for an engine that counts skipped rows against its limit. It
        // must not turn an idle poll into twelve queries.
        assertThat(queue.claim(5, "worker", List.of())).isEmpty();
    }

    @Test
    @DisplayName("claiming zero is not a query")
    void zeroIsNoQuery() {
        enqueue(1, null);

        assertThat(queue.claim(0, "worker", List.of())).isEmpty();
        assertThat(scans.countByStatus(ScanStatus.PENDING.wireName())).isEqualTo(1);
    }

    @Test
    @DisplayName("concurrent polls of one agent never take it past its limit")
    void concurrentPollsRespectTheLimit() throws Exception {
        // Eight polls of one agent at once, round after round. Most interleavings are also turned
        // away by the conditional take — the polls mostly read the same oldest candidate — so this
        // is the broad check, and `theCountWaitsForAConcurrentTake` is the one that forces the
        // interleaving only the lock on the agent's row stops.
        //
        // Rounds, for the same reason as above: a round is a poll, and asserting after several is
        // what shows a full agent stays full rather than being topped up by a later race.
        enqueue(20, null);
        UUID edge = agent("edge");
        UUID other = agent("other");
        int limit = 2;
        int polls = 8;

        try (ExecutorService pool = Executors.newFixedThreadPool(polls)) {
            for (int round = 0; round < 5; round++) {
                CyclicBarrier together = new CyclicBarrier(polls);
                List<Callable<Optional<ScanEntity>>> claims = IntStream.range(0, polls)
                        .mapToObj(poll -> (Callable<Optional<ScanEntity>>) () -> {
                            together.await(10, TimeUnit.SECONDS);
                            return queue.claimWithin(edge, limit, List.of(), ScanQueue.Exclusion.NONE).scan();
                        })
                        .toList();
                for (Future<Optional<ScanEntity>> claim : pool.invokeAll(claims)) {
                    claim.get();
                }
                assertThat(scans.countByStatusAndClaimedBy(ScanStatus.SCANNING.wireName(), edge.toString()))
                        .as("scans held by an agent whose limit is %d, after round %d", limit, round)
                        .isEqualTo(limit);
            }
        }

        // The limit is the agent's, not the queue's: another agent still finds work.
        assertThat(queue.claimWithin(other, 1, List.of(), ScanQueue.Exclusion.NONE).scan()).isPresent();
    }

    @Test
    @DisplayName("a poll counts after a concurrent take of the same agent has committed, not before")
    void theCountWaitsForAConcurrentTake() throws Exception {
        // The interleaving the barrage above rarely produces, forced: another poll of the same
        // agent holds its row and has taken a *different* scan — one requeued behind the oldest,
        // say — without committing yet. Counting now would see the agent idle and take the oldest,
        // and the agent would hold two under a limit of one. The claim must wait on the row, then
        // count the take it was waiting for.
        enqueue(2, null);
        UUID edge = agent("edge");
        List<ScanEntity> queued = scans.findClaimableUnlabelled(ScanStatus.PENDING.wireName(), org.springframework.data.domain.Limit.of(2));
        long newest = queued.get(1).getId();
        CountDownLatch holding = new CountDownLatch(1);

        try (ExecutorService pool = Executors.newFixedThreadPool(2)) {
            Future<Boolean> competitor = pool.submit(() -> transactions.execute(status -> {
                Instant now = Instant.now();
                agents.lockForClaim(edge, now);
                boolean took = scans.take(newest, ScanStatus.PENDING.wireName(), ScanStatus.SCANNING.wireName(),
                        edge.toString(), now, now.plusSeconds(600)) == 1;
                holding.countDown();
                try {
                    // Uncommitted while the claim below counts, reads its candidate and reaches
                    // the agent's row.
                    Thread.sleep(1_500);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                }
                return took;
            }));
            assertThat(holding.await(10, TimeUnit.SECONDS)).isTrue();
            Future<Optional<ScanEntity>> claim = pool.submit(() -> queue.claimWithin(edge, 1, List.of(), ScanQueue.Exclusion.NONE).scan());

            assertThat(competitor.get(30, TimeUnit.SECONDS)).isTrue();
            assertThat(claim.get(30, TimeUnit.SECONDS)).as("a claim past a limit of one").isEmpty();
        }

        assertThat(scans.countByStatusAndClaimedBy(ScanStatus.SCANNING.wireName(), edge.toString())).isEqualTo(1);
    }

    @Test
    @DisplayName("a lapsed lease no longer holds a slot, a live one does")
    void aLapsedLeaseDoesNotCount() {
        enqueue(3, null);
        UUID edge = agent("edge");

        long held = queue.claimWithin(edge, 1, List.of(), ScanQueue.Exclusion.NONE).scan().orElseThrow().getId();
        assertThat(queue.claimWithin(edge, 1, List.of(), ScanQueue.Exclusion.NONE).scan()).as("a live lease fills a limit of one").isEmpty();

        // The agent died mid-scan: its lease runs out before any reclaim has put the row back.
        // Counting it would keep the restarted agent idle until somebody else's timer fired.
        ScanEntity stored = scans.findById(held).orElseThrow();
        stored.setLeaseExpiresAt(Instant.now().minusSeconds(60));
        scans.save(stored);

        assertThat(queue.claimWithin(edge, 1, List.of(), ScanQueue.Exclusion.NONE).scan()).isPresent();
    }

    /**
     * The selection of an agent that cannot be handed a delegated credential (decision 0031): the
     * repositories carrying one are left out, and their scans wait untouched — no claim, so no
     * attempt counted — while what the agent can run behind them is taken. Both shapes of the
     * selection, with and without labels, because each is its own statement on every engine.
     */
    @Test
    @DisplayName("an excluded repository's scans stay pending and unclaimed, and what follows them is taken")
    void anExclusionLeavesTheScansWhereTheyAre() {
        for (String label : new String[] {null, "dmz"}) {
            scans.deleteAll();
            long keyed = repository("keyed-" + label);
            long open = repository("open-" + label);
            List<String> labels = label == null ? List.of() : List.of(label);
            enqueueFor(keyed, 2, label);
            enqueue(1, label);
            enqueueFor(open, 1, label);
            // Routed to other agents: not this one's to take, so not among what it is asked to leave out.
            enqueueFor(repository("routed-" + label), 1, "elsewhere");
            UUID edge = agent("edge-" + label);

            List<ScanEntity> taken = new ArrayList<>();
            java.util.Set<Long> asked = new java.util.HashSet<>();
            ScanQueue.Exclusion recording = repositories -> {
                asked.addAll(repositories);
                return excluding(keyed).among(repositories);
            };
            for (int poll = 0; poll < 4; poll++) {
                queue.claimWithin(edge, 16, labels, recording).scan().ifPresent(taken::add);
            }
            // Routed to other agents: not this one's to take, so never asked about.
            assertThat(asked).as("with label %s", label).isSubsetOf(keyed, open);

            assertThat(taken).as("with label %s", label).hasSize(2)
                    .allSatisfy(scan -> assertThat(scan.getRepoId()).isNotEqualTo(Long.valueOf(keyed)));
            assertThat(scans.findAll())
                    .filteredOn(scan -> Long.valueOf(keyed).equals(scan.getRepoId()))
                    .hasSize(2)
                    .allSatisfy(scan -> {
                        assertThat(scan.getStatus()).isEqualTo(ScanStatus.PENDING.wireName());
                        assertThat(scan.getClaimedBy()).isNull();
                        assertThat(scan.getAttempts()).isZero();
                    });
            // Nothing excluded: the same agent takes them, which is what a verified one does.
            assertThat(queue.claimWithin(edge, 16, labels, ScanQueue.Exclusion.NONE).scan()).get()
                    .extracting(ScanEntity::getRepoId).isEqualTo(keyed);
        }
    }

    /**
     * The exclusion used to travel as {@code not in :excluded}, one bind parameter per waiting
     * repository carrying a credential: past 65,535 the PostgreSQL driver refuses the statement
     * before sending it, and the claim failed on every poll of every agent that needed it. Now the queue is walked a page at a time
     * and only a page's repositories are asked about, so this pins both halves: the scan behind two
     * full pages of excluded ones is still found, and the exclusion is never asked about more than
     * a page — which is what keeps every statement, here and in the owner's lookup, under the limits.
     */
    @Test
    @DisplayName("a restricted agent reads the queue a page at a time and still finds the scan behind the excluded ones")
    void theExclusionIsAskedAPageAtATime() {
        int excludedRepositories = 2 * ScanQueue.PAGE + 10;
        java.util.Set<Long> keyed = new java.util.HashSet<>();
        for (int i = 0; i < excludedRepositories; i++) {
            long id = repository("keyed-" + i);
            keyed.add(id);
            enqueueFor(id, 1, null);
        }
        long open = repository("open");
        enqueueFor(open, 1, null);
        UUID edge = agent("edge");

        java.util.List<Integer> askedSizes = new ArrayList<>();
        ScanQueue.Exclusion carryingCredentials = repositories -> {
            askedSizes.add(repositories.size());
            return repositories.stream().filter(keyed::contains).collect(java.util.stream.Collectors.toSet());
        };

        ScanQueue.AgentClaim claim = queue.claimWithin(edge, 16, List.of(), carryingCredentials);

        assertThat(claim.scan()).get().extracting(ScanEntity::getRepoId).isEqualTo(open);
        assertThat(claim.kept()).as("the scans it walked past were left for another executor").isTrue();
        assertThat(askedSizes).as("repositories asked about at once").hasSizeGreaterThan(2)
                .allSatisfy(size -> assertThat(size).isLessThanOrEqualTo(ScanQueue.PAGE));
        assertThat(scans.findAll()).filteredOn(scan -> keyed.contains(scan.getRepoId()))
                .allSatisfy(scan -> assertThat(scan.getStatus()).isEqualTo(ScanStatus.PENDING.wireName()));

        // Nothing left that it may take: nothing claimed, and it is told it was kept from the rest.
        ScanQueue.AgentClaim nothing = queue.claimWithin(edge, 16, List.of(), carryingCredentials);
        assertThat(nothing.scan()).isEmpty();
        assertThat(nothing.kept()).isTrue();
    }

    /**
     * The owner's half of the same limit: asked about more repositories than any engine binds in one
     * statement — the figure of the scans nobody can take asks about every waiting repository — the
     * lookup answers instead of failing. All but two of these identifiers name nothing, which costs no
     * rows and binds every one of them.
     */
    @Test
    @DisplayName("the credential lookup answers for more repositories than an engine binds at once")
    void theCredentialLookupIsBatched() {
        com.asmolabs.vectispire.core.targets.persistence.SshKeyEntity key =
                new com.asmolabs.vectispire.core.targets.persistence.SshKeyEntity();
        key.setId(UUID.randomUUID());
        key.setName("deploy");
        key.setPrivateKey("v2:not-read-by-this-test");
        key.setCreatedAt(Instant.now());
        sshKeys.save(key);
        long keyed = repository("keyed");
        RepositoryEntity row = repositories.findById(keyed).orElseThrow();
        row.setSshKeyId(key.getId());
        repositories.save(row);
        long open = repository("open");

        List<Long> ids = new ArrayList<>(java.util.stream.LongStream.rangeClosed(1_000_000, 1_070_000).boxed().toList());
        ids.add(keyed);
        ids.add(open);

        assertThat(targets.carryingCredentials(ids)).containsExactly(keyed);
    }

    @Test
    @DisplayName("a refunded requeue gives back the claim's attempt, and only to the claim's owner")
    void aRefundGivesBackTheClaimsAttempt() {
        enqueue(1, null);
        UUID edge = agent("edge");
        long id = queue.claimWithin(edge, 1, List.of(), ScanQueue.Exclusion.NONE).scan().orElseThrow().getId();
        assertThat(scans.findById(id).orElseThrow().getAttempts()).isEqualTo(1);

        assertThat(queue.requeueRefunded(id, "somebody-else")).isFalse();
        assertThat(scans.findById(id).orElseThrow().getAttempts()).isEqualTo(1);

        assertThat(queue.requeueRefunded(id, edge.toString())).isTrue();
        ScanEntity after = scans.findById(id).orElseThrow();
        assertThat(after.getStatus()).isEqualTo(ScanStatus.PENDING.wireName());
        assertThat(after.getClaimedBy()).isNull();
        assertThat(after.getLeaseExpiresAt()).isNull();
        assertThat(after.getAttempts()).isZero();

        // The plain requeue keeps the attempt: a scan that keeps going undelivered reaches its limit.
        queue.claimWithin(edge, 1, List.of(), ScanQueue.Exclusion.NONE).scan().orElseThrow();
        assertThat(queue.requeue(id, edge.toString())).isTrue();
        assertThat(scans.findById(id).orElseThrow().getAttempts()).isEqualTo(1);
    }

    /**
     * Agents that must leave a repository out and agents that need not, polling at once, round after
     * round. The take is the conditional update it always was; what this pins is that narrowing the
     * selection neither hands a scan to two of them nor strands one — every scan claimed exactly once,
     * each at its first attempt, and none of the excluded repository's scans by an agent that
     * excluded it.
     */
    @Test
    @DisplayName("agents excluding a repository and agents that do not, at once: each scan once, to one allowed")
    void exclusionsUnderConcurrency() throws Exception {
        long keyed = repository("keyed");
        long open = repository("open");
        enqueueFor(keyed, 10, null);
        enqueueFor(open, 5, null);
        enqueue(5, null);
        List<UUID> withholding = IntStream.range(0, 4).mapToObj(i -> agent("unverified-" + i)).toList();
        List<UUID> capable = IntStream.range(0, 4).mapToObj(i -> agent("verified-" + i)).toList();
        record Claim(UUID agent, boolean excluding, ScanEntity scan) {}
        List<Claim> served = new ArrayList<>();

        try (ExecutorService pool = Executors.newFixedThreadPool(8)) {
            for (int round = 0; round < 20 && served.size() < 20; round++) {
                CyclicBarrier together = new CyclicBarrier(8);
                List<Callable<Optional<Claim>>> polls = new ArrayList<>();
                for (UUID agent : withholding) {
                    polls.add(() -> {
                        together.await(10, TimeUnit.SECONDS);
                        return queue.claimWithin(agent, 16, List.of(), excluding(keyed)).scan().map(scan -> new Claim(agent, true, scan));
                    });
                }
                for (UUID agent : capable) {
                    polls.add(() -> {
                        together.await(10, TimeUnit.SECONDS);
                        return queue.claimWithin(agent, 16, List.of(), ScanQueue.Exclusion.NONE).scan().map(scan -> new Claim(agent, false, scan));
                    });
                }
                for (Future<Optional<Claim>> poll : pool.invokeAll(polls)) {
                    poll.get().ifPresent(served::add);
                }
            }
        }

        assertThat(served).extracting(claim -> claim.scan().getId()).doesNotHaveDuplicates().hasSize(20);
        assertThat(served).filteredOn(Claim::excluding)
                .allSatisfy(claim -> assertThat(claim.scan().getRepoId()).isNotEqualTo(Long.valueOf(keyed)));
        assertThat(scans.findAll()).allSatisfy(scan -> {
            assertThat(scan.getStatus()).isEqualTo(ScanStatus.SCANNING.wireName());
            assertThat(scan.getAttempts()).as("scan %d", scan.getId()).isEqualTo(1);
        });
    }

    /** Claims one scan for {@code worker}, then makes its lease lapse as a silent worker's would. */
    private long claimedThenLapsed(String worker) {
        enqueue(1, null);
        ScanEntity scan = queue.claim(1, worker, List.of()).getFirst();
        ScanEntity stored = scans.findById(scan.getId()).orElseThrow();
        stored.setLeaseExpiresAt(Instant.now().minusSeconds(60));
        scans.save(stored);
        return scan.getId();
    }

    /**
     * An agent's failure report, on every engine: the lapse's rule applied at once, and only to the
     * attempt it names. The last half forces the window the statement's own condition exists for —
     * the lease lapsing and the same agent taking the scan again between the report's read and its
     * write — by issuing the write after the retake.
     */
    @Test
    @DisplayName("a failure report requeues with the reason, fails at the last attempt, and reaches no later attempt")
    void aFailureReportEndsItsAttemptOnly() {
        enqueue(1, null);
        UUID edge = agent("edge");
        long id = queue.claimWithin(edge, 1, List.of(), ScanQueue.Exclusion.NONE).scan().orElseThrow().getId();

        assertThat(queue.abandon(id, "somebody-else", 1, done -> "not mine")).isEmpty();
        assertThat(queue.abandon(id, edge.toString(), 2, done -> "not this attempt")).isEmpty();
        assertThat(queue.abandon(id, edge.toString(), 1, done -> "attempt " + done.attempt() + ": clone refused"))
                .hasValueSatisfying(done -> assertThat(done.outcome())
                        .isEqualTo(com.asmolabs.vectispire.common.domain.scans.ScanQueue.Lapsed.REQUEUE));
        ScanEntity requeued = scans.findById(id).orElseThrow();
        assertThat(requeued.getStatus()).isEqualTo(ScanStatus.PENDING.wireName());
        assertThat(requeued.getError()).isEqualTo("attempt 1: clone refused");
        assertThat(requeued.getClaimedBy()).isNull();
        assertThat(queue.abandon(id, edge.toString(), 1, done -> "again")).isEmpty();

        queue.claimWithin(edge, 1, List.of(), ScanQueue.Exclusion.NONE).scan().orElseThrow();
        assertThat(scans.releaseOwnedAttempt(
                        id, ScanStatus.SCANNING.wireName(), edge.toString(), 1, ScanStatus.PENDING.wireName(), "stale"))
                .isZero();
        assertThat(scans.findById(id).orElseThrow().getStatus()).isEqualTo(ScanStatus.SCANNING.wireName());

        assertThat(queue.abandon(id, edge.toString(), 2, done -> "clone refused")).isPresent();
        queue.claimWithin(edge, 1, List.of(), ScanQueue.Exclusion.NONE).scan().orElseThrow();
        assertThat(queue.abandon(id, edge.toString(), 3, done -> "the last"))
                .hasValueSatisfying(done -> assertThat(done.outcome())
                        .isEqualTo(com.asmolabs.vectispire.common.domain.scans.ScanQueue.Lapsed.FAIL));
        ScanEntity failed = scans.findById(id).orElseThrow();
        assertThat(failed.getStatus()).isEqualTo(ScanStatus.FAILED.wireName());
        assertThat(failed.getError()).isEqualTo("the last");
        assertThat(failed.getLeaseExpiresAt()).isNull();
    }

    @Test
    @DisplayName("a deposed worker cannot fail the scan its successor now holds")
    void aDeposedWorkerCannotFailItsSuccessor() {
        // The release named the row by id alone: the first worker, whose lease had lapsed, marked
        // the successor's scan FAILED and dropped the successor's lease with it.
        long id = claimedThenLapsed("worker-a");
        assertThat(queue.reclaimLapsedLeases().requeued()).containsExactly(id);
        assertThat(queue.claim(1, "worker-b", List.of())).extracting(ScanEntity::getId).containsExactly(id);

        assertThat(queue.fail(id, "worker-a", "runner crashed")).isFalse();
        assertThat(queue.requeue(id, "worker-a")).isFalse();

        ScanEntity after = scans.findById(id).orElseThrow();
        assertThat(after.getStatus()).isEqualTo(ScanStatus.SCANNING.wireName());
        assertThat(after.getClaimedBy()).isEqualTo("worker-b");
        assertThat(after.getLeaseExpiresAt()).isNotNull();
    }

    @Test
    @DisplayName("a renewal landing between the reclaim's read and its update wins")
    void aRenewalBeatsAStaleReclaim() throws Exception {
        // The reclaim reads the lapsed scans, then releases them. A renewal committed in between
        // must survive: the release is conditioned on the lease still being lapsed, and without
        // that condition a worker renewing on time was deposed anyway.
        long id = claimedThenLapsed("worker-a");
        CountDownLatch renewed = new CountDownLatch(1);

        try (ExecutorService pool = Executors.newFixedThreadPool(2)) {
            Future<Boolean> renewal = pool.submit(() -> transactions.execute(status -> {
                boolean ok = queue.renewLease(id, "worker-a");
                renewed.countDown();
                try {
                    // Uncommitted while the reclaim reads the old, lapsed lease and then blocks on
                    // the row this transaction holds.
                    Thread.sleep(1_500);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                }
                return ok;
            }));
            assertThat(renewed.await(10, TimeUnit.SECONDS)).isTrue();
            Future<ScanQueue.Reclaimed> reclaim = pool.submit(() -> queue.reclaimLapsedLeases());

            assertThat(renewal.get(30, TimeUnit.SECONDS)).isTrue();
            assertThat(reclaim.get(30, TimeUnit.SECONDS).requeued()).isEmpty();
        }

        ScanEntity after = scans.findById(id).orElseThrow();
        assertThat(after.getStatus()).isEqualTo(ScanStatus.SCANNING.wireName());
        assertThat(after.getClaimedBy()).isEqualTo("worker-a");
    }

    @Test
    @DisplayName("a reclaim racing the final write waits for it, then changes nothing")
    void theWriteFencesTheReclaim() throws Exception {
        // The ownership check was a plain read: a reclaim and a new take could commit between it
        // and the final save, which then merged stale results over the successor's claim. The
        // check is now an update, whose row lock the write keeps until it commits.
        long id = claimedThenLapsed("worker-a");
        CountDownLatch held = new CountDownLatch(1);

        try (ExecutorService pool = Executors.newFixedThreadPool(2)) {
            Future<Boolean> write = pool.submit(() -> transactions.execute(status -> {
                if (!queue.holdForWrite(id, "worker-a")) {
                    return false;
                }
                held.countDown();
                try {
                    // Long enough for the reclaim below to reach the row and block on it.
                    Thread.sleep(1_500);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                }
                ScanEntity scan = scans.findById(id).orElseThrow();
                scan.setStatus(ScanStatus.COMPLETED.wireName());
                scan.setClaimedBy(null);
                scan.setLeaseExpiresAt(null);
                scans.save(scan);
                return true;
            }));
            assertThat(held.await(10, TimeUnit.SECONDS)).isTrue();
            Future<ScanQueue.Reclaimed> reclaim = pool.submit(() -> queue.reclaimLapsedLeases());

            assertThat(write.get(30, TimeUnit.SECONDS)).isTrue();
            assertThat(reclaim.get(30, TimeUnit.SECONDS).requeued()).isEmpty();
        }

        assertThat(scans.findById(id).orElseThrow().getStatus()).isEqualTo(ScanStatus.COMPLETED.wireName());
    }
}
