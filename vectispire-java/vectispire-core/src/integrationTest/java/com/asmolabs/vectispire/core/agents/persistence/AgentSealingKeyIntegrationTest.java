package com.asmolabs.vectispire.core.agents.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.crypto.SealedEnvelope;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.persistence.Engine;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * The statement that decides which sealing key an agent's credentials are sealed for, on each engine.
 *
 * <p>The condition compares a nullable {@code bigint} and a string in one {@code where}: three-valued
 * logic on a null generation, and a generation — epoch milliseconds — past what a 32-bit column
 * holds. SQLite, which the HTTP suite runs on, stores any integer in any column and reads nothing
 * of the declared width, so only the two deployable engines can say the comparison holds.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("accepting a sealing key on a real engine")
class AgentSealingKeyIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final Optional<JdbcDatabaseContainer<?>> CONTAINER = ENGINE.container();

    /** 2026-09-26 in epoch milliseconds: larger than an int, which is the point. */
    private static final long NOW = 1_790_380_800_000L;

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
    private AgentRepository agents;

    private final SealedEnvelope envelopes = new SealedEnvelope();

    private UUID agent() {
        AgentEntity agent = new AgentEntity();
        agent.setName("sealing-" + UUID.randomUUID());
        agent.setKind("remote");
        agent.setCredentialsMode("delegated");
        agent.setEnabled(true);
        agent.setCreatedAt(Instant.now());
        return agents.save(agent).getId();
    }

    @Test
    @DisplayName("the first key is taken, a newer one replaces it, and an older one or a rival never does")
    void onlyForwards() {
        UUID id = agent();
        String first = envelopes.generateKeyPair().publicKey();
        String second = envelopes.generateKeyPair().publicKey();

        assertThat(agents.acceptSealingKey(id, first, NOW)).isOne();
        assertThat(agents.acceptSealingKey(id, first, NOW)).as("the same key repeated").isOne();
        assertThat(agents.acceptSealingKey(id, second, NOW)).as("another key, same generation").isZero();
        assertThat(agents.acceptSealingKey(id, second, NOW - 1)).as("an older generation").isZero();
        assertThat(agents.acceptSealingKey(id, second, NOW + 1)).as("a newer generation").isOne();

        AgentEntity row = agents.findById(id).orElseThrow();
        assertThat(row.getSealingPublicKey()).isEqualTo(second);
        assertThat(row.getSealingKeyGeneration()).isEqualTo(NOW + 1);
    }

    @Test
    @DisplayName("a heartbeat leaves the key alone, and saving the row does not write it")
    void nothingElseWritesIt() {
        UUID id = agent();
        String key = envelopes.generateKeyPair().publicKey();
        AgentEntity readBefore = agents.findById(id).orElseThrow();
        agents.acceptSealingKey(id, key, NOW);

        agents.recordHeartbeat(id, Instant.now(), "host", "linux", "1.0", "docker", null, "1");
        readBefore.setLabels("dmz");
        agents.save(readBefore);

        AgentEntity row = agents.findById(id).orElseThrow();
        assertThat(row.getLabels()).isEqualTo("dmz");
        assertThat(row.getSealingPublicKey()).isEqualTo(key);
        assertThat(row.getSealingKeyGeneration()).isEqualTo(NOW);
    }
}
