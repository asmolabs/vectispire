package com.asmolabs.vectispire.core.forges;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.forges.DiscoveryState;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.forges.persistence.ForgeDiscoveryEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeDiscoveryRepository;
import com.asmolabs.vectispire.core.forges.persistence.ForgeRepositoryEntity;
import com.asmolabs.vectispire.core.forges.persistence.ForgeRepositoryRepository;
import com.asmolabs.vectispire.core.persistence.Engine;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * The discoveries' queue and their snapshot on a real engine (decision 0037 §3, lot D3, V76): the active key that
 * keeps one discovery per connection — a unique index that must admit any number of ended runs, whose key is null —
 * the conditional take two instances race on, the owner's renewal and finish, the lapsed lease put back or failed,
 * and the snapshot's key, its widest values, the comparison's counts and gone marking, and the deletion with the
 * connection.
 *
 * <p>Each is a statement an engine could answer differently: a unique index counting nulls as equal would refuse a
 * connection's second discovery, and a {@code varchar(1000)} path or a timestamp's precision is what MySQL checks.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("forge discoveries on the engine")
class ForgeDiscoveryIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final JdbcDatabaseContainer<?> CONTAINER = ENGINE.container();

    private static final Instant AT = Instant.parse("2026-10-03T10:00:00.123456Z");
    private static final String PENDING = DiscoveryState.PENDING.wireName();
    private static final String RUNNING = DiscoveryState.RUNNING.wireName();

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
    private ForgeDiscoveryRepository discoveries;

    @Autowired
    private ForgeRepositoryRepository snapshot;

    @BeforeEach
    void empty() {
        snapshot.deleteAll();
        discoveries.deleteAll();
    }

    private ForgeDiscoveryEntity run(UUID connection, String state, String activeKey, Instant requestedAt) {
        ForgeDiscoveryEntity run = new ForgeDiscoveryEntity();
        run.setConnectionId(connection);
        run.setState(state);
        run.setActiveKey(activeKey);
        run.setRequestedAt(requestedAt);
        run.setRequestedBy("ada");
        return discoveries.saveAndFlush(run);
    }

    @Test
    @DisplayName("ended runs share the null key; a second active run for the connection is refused")
    void oneActiveRunPerConnection() {
        UUID connection = UUID.randomUUID();
        for (int i = 0; i < 3; i++) {
            run(connection, DiscoveryState.COMPLETED.wireName(), null, AT.plusSeconds(i));
        }
        run(connection, PENDING, connection.toString(), AT);

        assertThatThrownBy(() -> run(connection, PENDING, connection.toString(), AT))
                .isInstanceOf(DataIntegrityViolationException.class);
        assertThat(discoveries.findByActiveKey(connection.toString())).isPresent();
        assertThat(discoveries.count()).isEqualTo(4);
    }

    @Test
    @DisplayName("two instances read the same run: the conditional take lets exactly one of them have it")
    void racingTakes() {
        long older = run(UUID.randomUUID(), PENDING, "a", AT).getId();
        run(UUID.randomUUID(), PENDING, "b", AT.plusSeconds(5));

        // Both read before either takes — the interleaving forced, not hoped for.
        List<Long> east = discoveries.waiting(PENDING, PageRequest.of(0, 8));
        List<Long> west = discoveries.waiting(PENDING, PageRequest.of(0, 8));
        assertThat(east).first().isEqualTo(older);
        assertThat(west).first().isEqualTo(older);

        assertThat(discoveries.take(east.getFirst(), PENDING, RUNNING, "east", AT, AT.plusSeconds(60))).isOne();
        assertThat(discoveries.take(west.getFirst(), PENDING, RUNNING, "west", AT, AT.plusSeconds(60))).isZero();
        ForgeDiscoveryEntity taken = discoveries.findById(older).orElseThrow();
        assertThat(taken.getClaimedBy()).isEqualTo("east");
        assertThat(taken.getAttempts()).isOne();
    }

    @Test
    @DisplayName("only the owner renews and ends its run; a lapsed lease is put back while attempts remain, then failed")
    void ownerAndLease() {
        long id = run(UUID.randomUUID(), PENDING, "k", AT).getId();
        discoveries.take(id, PENDING, RUNNING, "east", AT, AT.plusSeconds(60));

        assertThat(discoveries.renew(id, RUNNING, "west", AT.plusSeconds(120), 1, 2, 0, 3, 4)).isZero();
        assertThat(discoveries.renew(id, RUNNING, "east", AT.plusSeconds(120), 1, 2, 0, 3, 4)).isOne();
        assertThat(discoveries.lapsed(RUNNING, AT.plusSeconds(100))).doesNotContain(id);

        assertThat(discoveries.requeueLapsed(id, RUNNING, PENDING, AT.plusSeconds(121), 3)).isOne();
        assertThat(discoveries.take(id, PENDING, RUNNING, "west", AT, AT.plusSeconds(60))).isOne();
        ForgeDiscoveryEntity resumed = discoveries.findById(id).orElseThrow();
        assertThat(resumed.getAttempts()).isEqualTo(2);
        assertThat(resumed.getRepositoriesSeen()).as("a resumed run lists again from the start").isZero();
        assertThat(finish(id, "east")).as("the instance that lost it writes nothing").isZero();

        assertThat(discoveries.requeueLapsed(id, RUNNING, PENDING, AT.plusSeconds(61), 2)).as("attempts spent").isZero();
        assertThat(discoveries.failLapsed(id, RUNNING, "failed", "executor_lost", "lost", AT.plusSeconds(61), 2)).isOne();
        ForgeDiscoveryEntity failed = discoveries.findById(id).orElseThrow();
        assertThat(failed.getState()).isEqualTo("failed");
        assertThat(failed.getActiveKey()).isNull();

        long next = run(UUID.randomUUID(), PENDING, "n", AT).getId();
        discoveries.take(next, PENDING, RUNNING, "east", AT, AT.plusSeconds(60));
        assertThat(finish(next, "east")).isOne();
        ForgeDiscoveryEntity completed = discoveries.findById(next).orElseThrow();
        assertThat(completed.getState()).isEqualTo("completed");
        assertThat(completed.getGoneCount()).isNull();
        assertThat(completed.getRateLimitResetAt()).isEqualTo(AT.plusSeconds(3600));
        assertThat(completed.getActiveKey()).isNull();
    }

    private int finish(long id, String owner) {
        return discoveries.finish(id, RUNNING, owner, "completed", null, "d".repeat(2000), AT.plusSeconds(30), 4, 20_000, 1,
                20_300, 61, AT.plusSeconds(3600), 3, 2, null);
    }

    private ForgeRepositoryEntity repository(UUID connection, String forgeId, long seenBy) {
        ForgeRepositoryEntity row = new ForgeRepositoryEntity();
        row.setConnectionId(connection);
        row.setForgeId(forgeId);
        row.setFullPath("acme/" + "p".repeat(995));
        row.setNamespacePath("acme");
        row.setPersonal(false);
        row.setName("n".repeat(255));
        row.setHttpUrl("https://git.example.org/" + "u".repeat(1000));
        row.setChangeSummary("c".repeat(1500));
        row.setLastActivityAt(AT);
        row.setSizeBytes(5_000_000_000L);
        row.setFirstSeenBy(seenBy);
        row.setFirstSeenAt(AT);
        row.setLastSeenBy(seenBy);
        row.setLastSeenAt(AT);
        return snapshot.saveAndFlush(row);
    }

    @Test
    @DisplayName("the snapshot holds its widest values, one row per forge id, and marks gone what a run did not list")
    void theSnapshot() {
        UUID connection = UUID.randomUUID();
        UUID other = UUID.randomUUID();
        repository(connection, "1", 7);
        repository(connection, "2", 8);
        repository(connection, "3", 8);
        repository(other, "1", 7);

        assertThatThrownBy(() -> repository(connection, "1", 8)).isInstanceOf(DataIntegrityViolationException.class);
        ForgeRepositoryEntity read = snapshot.findByConnectionIdAndForgeIdIn(connection, List.of("1")).getFirst();
        assertThat(read.getFullPath()).hasSize(1000);
        assertThat(read.getLastActivityAt()).isEqualTo(AT);
        assertThat(read.getSizeBytes()).isEqualTo(5_000_000_000L);
        assertThat(read.getArchived()).as("unknown stays null").isNull();

        assertThat(snapshot.markGone(connection, 8, AT)).isOne();
        assertThat(snapshot.markGone(connection, 8, AT)).as("marked once").isZero();
        assertThat(snapshot.findByConnectionIdAndGoneBy(connection, 8, PageRequest.of(0, 10, Sort.by("fullPath", "id"))))
                .extracting(ForgeRepositoryEntity::getForgeId).containsExactly("1");
        assertThat(snapshot.countByConnectionIdAndFirstSeenBy(connection, 8)).isEqualTo(2);
        assertThat(snapshot.findByConnectionIdAndLastSeenBy(connection, 8, PageRequest.of(0, 1, Sort.by("fullPath", "id")))
                .getTotalElements()).isEqualTo(2);
        assertThat(snapshot.setLanguage(connection, "2", "TypeScript")).isOne();

        assertThat(discoveries.deleteByConnection(connection)).isZero();
        assertThat(snapshot.deleteByConnection(connection)).isEqualTo(3);
        assertThat(snapshot.findAll()).extracting(ForgeRepositoryEntity::getConnectionId).containsExactly(other);
    }
}
