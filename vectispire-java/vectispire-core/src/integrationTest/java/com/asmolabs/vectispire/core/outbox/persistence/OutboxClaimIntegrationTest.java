package com.asmolabs.vectispire.core.outbox.persistence;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.notifications.OutboxRetry;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.persistence.Engine;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.IntStream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.domain.Limit;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * Claiming notifications, against a real engine, from several instances at once.
 *
 * <p>Every instance runs the relay, and every one of them reads the same due rows. The claim is
 * the conditional update that decides which one sends; whether it holds under contention is a
 * property of the engine's isolation — MySQL's repeatable read in particular — and not something
 * a mock or a single thread can show. What it looks like when it does not hold: every webhook,
 * card and mail delivered once per instance.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("claiming from the notification outbox")
class OutboxClaimIntegrationTest {

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
    private Outbox messages;

    @BeforeEach
    void emptyOutbox() {
        messages.deleteAll();
    }

    @Test
    @DisplayName("each due message is claimed by exactly one of the instances racing for it")
    void eachMessageIsClaimedOnce() throws Exception {
        Instant created = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        messages.saveAll(IntStream.range(0, 20)
                .mapToObj(i -> {
                    OutboxMessageEntity message = new OutboxMessageEntity();
                    message.setId(UUID.randomUUID());
                    message.setMessageType("scan_delta");
                    message.setPayload("{}");
                    message.setStatus("pending");
                    message.setAttempts(0);
                    message.setCreatedAt(created.plusMillis(i));
                    return message;
                })
                .toList());

        // Each instance reads the due set first, exactly as the relay does, so every one of them
        // holds all twenty ids before any claim — the worst case, and the realistic one.
        Instant at = created.plusSeconds(1);
        Instant until = at.plus(OutboxRetry.CLAIM_WINDOW);
        int instances = 8;
        List<UUID> claimed = new ArrayList<>();

        try (ExecutorService pool = Executors.newFixedThreadPool(instances)) {
            List<Callable<List<UUID>>> passes = IntStream.range(0, instances)
                    .mapToObj(instance -> (Callable<List<UUID>>) () -> {
                        List<UUID> mine = new ArrayList<>();
                        for (OutboxMessageEntity due : messages.findDue("pending", at, Limit.of(20))) {
                            if (messages.claim(due.getId(), "pending", at, until) == 1) {
                                mine.add(due.getId());
                            }
                        }
                        return mine;
                    })
                    .toList();
            for (Future<List<UUID>> pass : pool.invokeAll(passes)) {
                claimed.addAll(pass.get());
            }
        }

        assertThat(claimed).as("a message claimed twice is a message delivered twice").doesNotHaveDuplicates();
        assertThat(claimed).as("and every due message is claimed by someone").hasSize(20);
    }
}
