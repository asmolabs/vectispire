package com.asmolabs.vectispire.core.forges;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.forges.DiscoveryState;
import com.asmolabs.vectispire.common.domain.forges.ImportSkip;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeImportRequest;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeImportResult;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeImportedTarget;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeMappingRule;
import com.asmolabs.vectispire.core.forges.ForgeImports.ForgeSkippedImport;
import com.asmolabs.vectispire.core.forges.persistence.ForgeConnectionEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeConnectionRepository;
import com.asmolabs.vectispire.core.forges.persistence.ForgeDiscoveryEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeDiscoveryRepository;
import com.asmolabs.vectispire.core.forges.persistence.ForgeImportLinkEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeImportLinkRepository;
import com.asmolabs.vectispire.core.forges.persistence.ForgeRepositoryEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeRepositoryRepository;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.targets.TargetImports;
import com.asmolabs.vectispire.core.targets.persistence.GitRepositoryRepository;
import com.asmolabs.vectispire.core.targets.persistence.RepositoryEntity;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
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
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * The import from a forge on a real engine (decision 0037 §5, lot D6, V78): two imports of one selection racing, the
 * provenance table's keys, and the reads sized by the data.
 *
 * <p><b>The race is forced, not hoped for.</b> The first import runs inside a transaction held open after its writes;
 * the second plans — it cannot see an uncommitted target — and writes until the engine reports it waiting on the
 * first one's key, the unique guard of V73. Only then is the first released. The second's write is then refused; it
 * rolls back, finds that what is committed now makes it create less, and runs again, skipping everything. Two imports
 * launched together would meet in the write a few runs in a hundred and pass the others without having tested the
 * guard.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("forge imports on the engine")
class ForgeImportIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final JdbcDatabaseContainer<?> CONTAINER = ENGINE.container();
    private static final RequestActor ACTOR = new RequestActor("import-race", null, null);
    private static final Instant AT = Instant.parse("2026-10-03T10:00:00.123456Z");

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
    private ForgeImportService imports;

    @Autowired
    private TargetImports targets;

    @Autowired
    private ForgeConnectionRepository connections;

    @Autowired
    private ForgeDiscoveryRepository discoveries;

    @Autowired
    private ForgeRepositoryRepository snapshot;

    @Autowired
    private ForgeImportLinkRepository links;

    @Autowired
    private GitRepositoryRepository repositories;

    @Autowired
    private PlatformTransactionManager transactions;

    private UUID connectionId;
    private long discoveryId;

    @BeforeEach
    void seeded() {
        links.deleteAll();
        snapshot.deleteAll();
        discoveries.deleteAll();
        connections.deleteAll();
        repositories.deleteAll();

        ForgeConnectionEntity connection = new ForgeConnectionEntity();
        connectionId = UUID.randomUUID();
        connection.setId(connectionId);
        connection.setName("GitLab " + connectionId);
        connection.setKind("gitlab");
        connection.setEdition("gitlab_self_managed");
        connection.setBaseUrl("https://git.example.org");
        connection.setInternalNetwork(true);
        connection.setToken("v2:not-read-by-an-import");
        connection.setCredentialKind("gitlab_bot");
        connection.setProbedAt(AT);
        connection.setCreatedAt(AT);
        connection.setCreatedBy("ada");
        connection.setUpdatedAt(AT);
        connection.setUpdatedBy("ada");
        connections.saveAndFlush(connection);

        ForgeDiscoveryEntity run = new ForgeDiscoveryEntity();
        run.setConnectionId(connectionId);
        run.setState(DiscoveryState.COMPLETED.wireName());
        run.setRequestedAt(AT);
        run.setRequestedBy("ada");
        discoveryId = discoveries.saveAndFlush(run).getId();

        List<ForgeRepositoryEntity> rows = new ArrayList<>();
        for (int i = 1; i <= 3; i++) {
            rows.add(row(String.valueOf(i), "acme/raced-" + i));
        }
        snapshot.saveAllAndFlush(rows);
    }

    private ForgeRepositoryEntity row(String forgeId, String path) {
        ForgeRepositoryEntity row = new ForgeRepositoryEntity();
        row.setConnectionId(connectionId);
        row.setForgeId(forgeId);
        row.setFullPath(path);
        row.setNamespacePath(path.substring(0, path.lastIndexOf('/')));
        row.setName(path.substring(path.lastIndexOf('/') + 1));
        row.setDefaultBranch("main");
        row.setVisibility("private");
        row.setHttpUrl("https://git.example.org/" + path + ".git");
        row.setSshUrl("git@git.example.org:" + path + ".git");
        row.setFirstSeenBy(discoveryId);
        row.setFirstSeenAt(AT);
        row.setLastSeenBy(discoveryId);
        row.setLastSeenAt(AT);
        return row;
    }

    /** Into no project, so that the first key both imports meet is the target's own guard (V73). */
    private ForgeImportRequest request() {
        return new ForgeImportRequest(discoveryId, List.of("1", "2", "3"),
                List.of(new ForgeMappingRule("acme", null, null, null, true)), null, null, null, null);
    }

    @Test
    @DisplayName("two imports of one selection: one creates the targets, the other waits on its key, loses, and skips them all")
    void oneWinsNoTwin() throws Exception {
        CountDownLatch written = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<ForgeImportResult> first = pool.submit(() -> new TransactionTemplate(transactions).execute(status -> {
                ForgeImportResult result = imports.apply(connectionId, request(), ACTOR);
                written.countDown();
                await(release);
                return result;
            }));
            assertThat(written.await(1, TimeUnit.MINUTES)).as("the first import wrote its targets").isTrue();

            Future<ForgeImportResult> second = pool.submit(() -> imports.apply(connectionId, request(), ACTOR));
            awaitALockWait(second);
            release.countDown();

            ForgeImportResult won = first.get(1, TimeUnit.MINUTES);
            ForgeImportResult lost = second.get(1, TimeUnit.MINUTES);
            assertThat(won.created()).extracting(ForgeImportedTarget::forgeId).containsExactly("1", "2", "3");
            assertThat(lost.created()).as("planned again from what is committed: nothing left to create").isEmpty();
            assertThat(lost.skipped()).extracting(ForgeSkippedImport::reason)
                    .containsOnly(ImportSkip.ALREADY_IMPORTED).hasSize(3);
            assertThat(repositories.findAll()).as("one target per repository, the first import's")
                    .extracting(RepositoryEntity::getId)
                    .containsExactlyInAnyOrderElementsOf(won.created().stream().map(ForgeImportedTarget::repositoryId).toList());
            assertThat(links.count()).isEqualTo(3);
        } finally {
            release.countDown();
            pool.shutdownNow();
        }
    }

    private ForgeImportLinkEntity link(UUID connection, String forgeId, long repositoryId) {
        ForgeImportLinkEntity link = new ForgeImportLinkEntity();
        link.setConnectionId(connection);
        link.setForgeId(forgeId);
        link.setRepositoryId(repositoryId);
        link.setDiscoveryId(discoveryId);
        link.setImportedAt(AT);
        link.setImportedBy("ada");
        return link;
    }

    @Test
    @DisplayName("the provenance keys: a repository of a connection once, a target from one place; deleted by target and by connection")
    void theLinkKeys() {
        links.saveAndFlush(link(connectionId, "1", 10L));
        assertThatThrownBy(() -> links.saveAndFlush(link(connectionId, "1", 11L)))
                .isInstanceOf(DataIntegrityViolationException.class);
        assertThatThrownBy(() -> links.saveAndFlush(link(UUID.randomUUID(), "1", 10L)))
                .isInstanceOf(DataIntegrityViolationException.class);
        UUID other = UUID.randomUUID();
        links.saveAndFlush(link(other, "1", 12L));
        links.saveAndFlush(link(connectionId, "2", 13L));
        assertThat(links.findAll()).extracting(ForgeImportLinkEntity::getImportedAt).allSatisfy(at ->
                assertThat(at).as("the timestamp's precision").isEqualTo(AT));

        assertThat(links.deleteByRepository(10L)).isOne();
        assertThat(links.countByConnectionId(connectionId)).isOne();
        assertThat(links.deleteByConnection(connectionId)).isOne();
        assertThat(links.findAll()).extracting(ForgeImportLinkEntity::getRepositoryId).containsExactly(12L);
    }

    @Test
    @DisplayName("what a discovery listed: first seen by it or before, last seen by it or after, not gone")
    void listedBy() {
        ForgeRepositoryEntity later = row("4", "acme/later");
        later.setFirstSeenBy(discoveryId + 1);
        later.setLastSeenBy(discoveryId + 1);
        ForgeRepositoryEntity gone = row("5", "acme/gone");
        gone.setGoneBy(discoveryId);
        gone.setGoneAt(AT);
        ForgeRepositoryEntity seenAgain = row("6", "acme/seen-again");
        seenAgain.setLastSeenBy(discoveryId + 1);
        snapshot.saveAllAndFlush(List.of(later, gone, seenAgain));

        assertThat(snapshot.listedBy(connectionId, discoveryId)).extracting(ForgeRepositoryEntity::getForgeId)
                .containsExactlyInAnyOrder("1", "2", "3", "6");
        assertThat(discoveries.findFirstByConnectionIdAndStateInOrderByRequestedAtDescIdDesc(connectionId,
                List.of("completed", "partial"))).map(ForgeDiscoveryEntity::getId).contains(discoveryId);
    }

    @Test
    @DisplayName("present by identity, asked of more identities than one statement binds — batched")
    void presentPastTheBindLimit() {
        // Past 65,535 the PostgreSQL driver refuses one statement; the MySQL server-side limit is the same order. A
        // discovery's twenty thousand repositories are forty thousand identities, so the lookup is batched.
        RepositoryEntity typed = new RepositoryEntity();
        typed.setUrl("https://git.example.org/acme/typed.git");
        typed.setBranch("main");
        typed.setUrlIdentity("git.example.org/acme/typed");
        long id = repositories.saveAndFlush(typed).getId();
        RepositoryEntity unkeyed = new RepositoryEntity();
        unkeyed.setUrl("git@git.example.org:Acme/Unkeyed.git");
        unkeyed.setBranch("main");
        long unkeyedId = repositories.saveAndFlush(unkeyed).getId();

        List<String> identities = new ArrayList<>(IntStream.range(0, 70_000)
                .mapToObj(i -> "git.example.org/bulk/repo-" + i).toList());
        identities.add("git.example.org/acme/typed");
        identities.add("git.example.org/acme/unkeyed");

        Map<String, List<Long>> present = targets.presentByIdentity(identities);
        assertThat(present).containsOnlyKeys("git.example.org/acme/typed", "git.example.org/acme/unkeyed");
        assertThat(present.get("git.example.org/acme/typed")).containsExactly(id);
        assertThat(present.get("git.example.org/acme/unkeyed")).as("a row the keying has not reached, by its URL")
                .containsExactly(unkeyedId);
    }

    /** Until the engine reports a session waiting on a lock — the second import blocked on the first one's key. */
    private static void awaitALockWait(Future<?> second) throws Exception {
        String waiting = switch (ENGINE) {
            case POSTGRES -> "select count(*) from pg_stat_activity where wait_event_type = 'Lock'";
            case MYSQL -> "select count(*) from performance_schema.data_lock_waits";
        };
        long deadline = System.nanoTime() + TimeUnit.MINUTES.toNanos(1);
        String user = ENGINE == Engine.MYSQL ? "root" : CONTAINER.getUsername();
        try (Connection connection = DriverManager.getConnection(CONTAINER.getJdbcUrl(), user, CONTAINER.getPassword());
                Statement statement = connection.createStatement()) {
            while (System.nanoTime() < deadline) {
                try (ResultSet count = statement.executeQuery(waiting)) {
                    if (count.next() && count.getLong(1) > 0) {
                        return;
                    }
                }
                if (second.isDone()) {
                    throw new AssertionError("the second import ended without ever waiting on the first: " + outcome(second));
                }
                Thread.sleep(20);
            }
        }
        throw new AssertionError("the second import never waited on the first one's key");
    }

    private static String outcome(Future<?> done) {
        try {
            return "returned " + done.get();
        } catch (Exception failed) {
            return "failed " + failed.getCause();
        }
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(1, TimeUnit.MINUTES)) {
                throw new IllegalStateException("never released");
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(interrupted);
        }
    }
}
