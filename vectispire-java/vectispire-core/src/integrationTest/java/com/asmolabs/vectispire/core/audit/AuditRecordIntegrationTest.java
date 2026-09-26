package com.asmolabs.vectispire.core.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import com.asmolabs.vectispire.common.domain.audit.AuditChain;
import com.asmolabs.vectispire.common.domain.audit.AuditOperation;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogEntity;
import com.asmolabs.vectispire.core.audit.persistence.AuditLogRepository;
import com.asmolabs.vectispire.core.persistence.Engine;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
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
 * Audit entries whose values exceed their columns, written to a real engine.
 *
 * <p><b>Only a real engine can say this.</b> SQLite, which the HTTP suite runs on, stores a string
 * of any length in a {@code varchar(255)}; MySQL and PostgreSQL refuse the row. The resource id of
 * a settings write is the joined list of its keys, and the one of a refused request is its URI —
 * neither has a length anybody bounded, and an over-long one made {@code record} throw at its
 * commit and lose the entry, on the engines deployments run and on no test.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("an over-long audit entry on a real engine")
class AuditRecordIntegrationTest {

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
        registry.add("vectispire.audit.mirror-path", MIRROR::toString);
    }

    /** A mirror, so that what a refused row leaves behind outside the table can be read. */
    private static final Path MIRROR = mirrorFile();

    private static Path mirrorFile() {
        try {
            Path directory = Files.createTempDirectory("vectispire-audit-mirror");
            directory.toFile().deleteOnExit();
            return directory.resolve("audit.ndjson");
        } catch (IOException failed) {
            throw new UncheckedIOException(failed);
        }
    }

    @Autowired
    private AuditLogService audit;

    @Autowired
    private AuditLogRepository entries;

    @Autowired
    private TransactionTemplate transactions;

    @BeforeEach
    void empty() throws IOException {
        entries.deleteAll();
        Files.deleteIfExists(MIRROR);
    }

    @Test
    @DisplayName("every column over its width is cut, and the entry is kept and verifies")
    void everyColumnIsCut() {
        AuditLogService.Record longest = new AuditLogService.Record(
                AuditOperation.SETTING_UPDATED,
                "key,".repeat(300),
                "€".repeat(400),
                "u".repeat(400),
                "1".repeat(100),
                "Mozilla/5.0 ".repeat(100));

        assertThatCode(() -> audit.record(longest)).doesNotThrowAnyException();

        assertThat(entries.findAll()).singleElement().satisfies(row -> {
            assertThat(row.getResourceId()).hasSize(255);
            assertThat(row.getDescription()).hasSize(255);
            assertThat(row.getUserId()).hasSize(255);
            assertThat(row.getIpAddress()).hasSize(64);
            assertThat(row.getUserAgent()).hasSize(255);
        });
        assertThat(audit.verify()).returns(null, AuditChain.Verification::broken);
    }

    @Test
    @DisplayName("an over-long entry recorded inside an action neither fails the action nor is lost")
    void insideAnAction() {
        String committed = transactions.execute(status -> {
            audit.record(AuditLogService.Record.of(
                    AuditOperation.ACCESS_DENIED, "/api/v1/" + "x".repeat(2000), "Refused", "bob"));
            return "done";
        });

        assertThat(committed).isEqualTo("done");
        assertThat(entries.findAll()).extracting(AuditLogEntity::getResourceId)
                .singleElement().asString().hasSize(255);
    }

    @Test
    @DisplayName("a row the engine refuses does not throw, and leaves no line in the mirror")
    void aRefusedRowLeavesNoTrace() {
        // A null description is refused by every engine. The INSERT used to wait for the commit:
        // the mirror line was written first, and the mirror then reported an entry the table
        // never kept.
        assertThatCode(() -> audit.record(AuditLogService.Record.of(
                AuditOperation.SETTING_UPDATED, "k", null, "alice"))).doesNotThrowAnyException();

        assertThat(entries.count()).isZero();
        assertThat(audit.verifyAgainstMirror())
                .returns(true, AuditLogService.MirrorComparison::configured)
                .returns(0, AuditLogService.MirrorComparison::missingFromTable);
    }
}
