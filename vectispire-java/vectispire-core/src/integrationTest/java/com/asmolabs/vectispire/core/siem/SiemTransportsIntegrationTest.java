package com.asmolabs.vectispire.core.siem;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.integrations.Integration;
import com.asmolabs.vectispire.common.domain.integrations.IntegrationDisabledException;
import com.asmolabs.vectispire.common.domain.integrations.IntegrationInUseException;
import com.asmolabs.vectispire.common.domain.siem.SiemProtocol;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.audit.RequestActor;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.settings.Integrations;
import com.asmolabs.vectispire.core.siem.persistence.SiemConfigEntity;
import com.asmolabs.vectispire.core.siem.persistence.SiemConfigRepository;
import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
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
 * The lock that keeps a SIEM save and the governor's switch of its transport from slipping between each other's
 * check and commit (decision 0040 §3, lot I3), on each engine: {@code for update} and {@code for share} on {@code
 * t_integration} and {@code t_siem_config}, read under PostgreSQL's read committed and MySQL's repeatable read — the
 * isolation is what decides whether the reader that waited sees the row the other committed, and the HTTP suite
 * runs on MySQL alone.
 *
 * <p>Both interleavings are forced with latches: one transaction is stopped inside its critical section while the
 * other arrives. Racing the two from threads passes with either lock removed most of the time.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("SIEM transports' in-use lock on the engine")
class SiemTransportsIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final JdbcDatabaseContainer<?> CONTAINER = ENGINE.container();
    private static final Integration UDP = Integration.of(SiemProtocol.SYSLOG_UDP);
    private static final RequestActor ACTOR = new RequestActor("siem-lock-test", null, null);

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
    private Integrations integrations;

    @Autowired
    private SiemExporterService exporter;

    @Autowired
    private SiemConfigRepository configs;

    @Autowired
    private TransactionTemplate transactions;

    private ExecutorService threads;

    @BeforeEach
    void exportingOverTcp() {
        threads = Executors.newFixedThreadPool(2);
        SiemConfigEntity row = configs.findById(SiemConfigEntity.SINGLETON_ID).orElseGet(SiemConfigEntity::new);
        row.setId(SiemConfigEntity.SINGLETON_ID);
        row.setEnabled(true);
        row.setProtocol(SiemProtocol.SYSLOG_TCP.name());
        row.setEndpoint("127.0.0.1:9");
        row.setMinSeverity("LOW");
        row.setUpdatedAt(Instant.now());
        configs.saveAndFlush(row);
    }

    @AfterEach
    void putBack() throws Exception {
        threads.shutdownNow();
        assertThat(threads.awaitTermination(60, TimeUnit.SECONDS)).isTrue();
        integrations.switchTo(UDP, true, "siem-lock-test");
        configs.deleteAll();
    }

    @Test
    @DisplayName("a switch arriving while a save holds the transport waits for it, then sees it in use")
    void aSwitchWaitsForTheSave() throws Exception {
        CountDownLatch holding = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Future<?> saving = threads.submit(() -> transactions.executeWithoutResult(status -> {
            integrations.holdEnabled(UDP);
            holding.countDown();
            await(release);
            SiemConfigEntity row = configs.findById(SiemConfigEntity.SINGLETON_ID).orElseThrow();
            row.setProtocol(SiemProtocol.SYSLOG_UDP.name());
            configs.save(row);
        }));
        assertThat(holding.await(30, TimeUnit.SECONDS)).isTrue();

        Future<Integrations.Switched> switching = threads.submit(() -> integrations.switchTo(UDP, false, "governor"));
        assertThatThrownBy(() -> switching.get(1_000, TimeUnit.MILLISECONDS)).isInstanceOf(TimeoutException.class);

        release.countDown();
        saving.get(60, TimeUnit.SECONDS);
        assertThatThrownBy(() -> switching.get(60, TimeUnit.SECONDS))
                .isInstanceOf(ExecutionException.class).hasCauseInstanceOf(IntegrationInUseException.class);
        assertThat(integrations.isEnabled(UDP)).isTrue();
    }

    @Test
    @DisplayName("a save arriving while a switch is still open waits for it, then reads the transport off")
    void aSaveWaitsForTheSwitch() throws Exception {
        CountDownLatch switched = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        Future<?> switching = threads.submit(() -> transactions.executeWithoutResult(status -> {
            assertThat(integrations.switchTo(UDP, false, "governor").changed()).isTrue();
            switched.countDown();
            await(release);
        }));
        assertThat(switched.await(30, TimeUnit.SECONDS)).isTrue();

        Future<?> saving = threads.submit(() -> exporter.saveConfig(true, "SYSLOG_UDP", "127.0.0.1:9", null, "LOW", null,
                ACTOR));
        assertThatThrownBy(() -> saving.get(1_000, TimeUnit.MILLISECONDS)).isInstanceOf(TimeoutException.class);

        release.countDown();
        switching.get(60, TimeUnit.SECONDS);
        assertThatThrownBy(() -> saving.get(60, TimeUnit.SECONDS))
                .isInstanceOf(ExecutionException.class).hasCauseInstanceOf(IntegrationDisabledException.class);
        assertThat(configs.findById(SiemConfigEntity.SINGLETON_ID).orElseThrow().getProtocol())
                .isEqualTo(SiemProtocol.SYSLOG_TCP.name());
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(60, TimeUnit.SECONDS)) {
                throw new IllegalStateException("never released");
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(interrupted);
        }
    }
}
