package com.asmolabs.vectispire.core.reportplugins;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.asmolabs.vectispire.common.domain.reportplugins.ProjectExportBounds;
import com.asmolabs.vectispire.common.domain.reportplugins.ReportRunState;
import com.asmolabs.vectispire.core.VectispireApplication;
import com.asmolabs.vectispire.core.persistence.Engine;
import com.asmolabs.vectispire.core.reportplugins.internal.ReportExportCeiling;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportDocumentEntity;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportDocumentRepository;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportExportEntity;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportExportRepository;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportRunEntity;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportRunRepository;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.PageRequest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.JdbcDatabaseContainer;

/**
 * The report runs' queue on a real engine (decision 0035 §2, lot R3, V75): the conditional take two executors
 * race on, the active key that keeps one run of a plugin per project — a unique index that must admit any number
 * of ended runs, whose key is null —, the owner's finish with every column the provenance reads (V77 added three),
 * the lapsed lease, an export's and a document's bytes kept, purged by age and by project through a subquery, and
 * an export stored whole at the run's bound — which MySQL's packet lowers.
 *
 * <p>Each is a statement an engine could answer differently: a unique index counting nulls as equal would refuse
 * the second report a project ever had, and a {@code delete … where run_id in (select …)} is what MySQL checks.
 */
@SpringBootTest(classes = VectispireApplication.class)
@DisplayName("report runs' queue on the engine")
class ReportRunQueueIntegrationTest {

    private static final Engine ENGINE = Engine.selected();
    private static final JdbcDatabaseContainer<?> CONTAINER = ENGINE.container();

    private static final Instant AT = Instant.parse("2026-10-03T10:00:00Z");
    private static final String PENDING = ReportRunState.PENDING.wireName();
    private static final String RUNNING = ReportRunState.RUNNING.wireName();

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
    private ReportRunRepository runs;

    @Autowired
    private ReportExportRepository exports;

    @Autowired
    private ReportExportCeiling ceiling;

    @Autowired
    private ReportDocumentRepository documents;

    @BeforeEach
    void empty() {
        documents.deleteAll();
        exports.deleteAll();
        runs.deleteAll();
    }

    private ReportRunEntity run(long projectId, String state, String activeKey, Instant requestedAt) {
        ReportRunEntity run = new ReportRunEntity();
        run.setProjectId(projectId);
        run.setPluginId("summary");
        run.setState(state);
        run.setActiveKey(activeKey);
        run.setRequestedAt(requestedAt);
        run.setRequestedBy("ada");
        run.setRequestedById(1L);
        return runs.saveAndFlush(run);
    }

    @Test
    @DisplayName("ended runs share the null key; a second active run of the plugin for the project is refused")
    void oneActiveRunPerPluginAndProject() {
        for (int i = 0; i < 3; i++) {
            run(1, ReportRunState.PRODUCED.wireName(), null, AT.plusSeconds(i));
        }
        run(1, PENDING, ReportRunService.activeKey("summary", 1), AT);
        run(2, PENDING, ReportRunService.activeKey("summary", 2), AT);

        assertThatThrownBy(() -> run(1, PENDING, ReportRunService.activeKey("summary", 1), AT))
                .isInstanceOf(DataIntegrityViolationException.class);
        assertThat(runs.existsByActiveKey(ReportRunService.activeKey("summary", 1))).isTrue();
        assertThat(runs.count()).isEqualTo(5);
    }

    @Test
    @DisplayName("two executors read the same run: the conditional take lets exactly one of them have it")
    void racingTakes() {
        long older = run(1, PENDING, ReportRunService.activeKey("summary", 1), AT).getId();
        run(2, PENDING, ReportRunService.activeKey("summary", 2), AT.plusSeconds(5));

        // Both read before either takes — the interleaving forced, not hoped for.
        List<Long> first = runs.waiting(PENDING, PageRequest.of(0, 8));
        List<Long> second = runs.waiting(PENDING, PageRequest.of(0, 8));
        assertThat(first).first().isEqualTo(older);
        assertThat(second).first().isEqualTo(older);

        assertThat(runs.take(first.getFirst(), PENDING, RUNNING, "east", AT, AT.plusSeconds(60))).isOne();
        assertThat(runs.take(second.getFirst(), PENDING, RUNNING, "west", AT, AT.plusSeconds(60))).isZero();
        assertThat(runs.findById(older).orElseThrow().getClaimedBy()).isEqualTo("east");
        assertThat(runs.waiting(PENDING, PageRequest.of(0, 8))).doesNotContain(older);
    }

    @Test
    @DisplayName("only the owner ends its run, and the end frees the key; a lapsed lease fails the run once")
    void ownerAndLease() {
        long id = run(1, PENDING, ReportRunService.activeKey("summary", 1), AT).getId();
        runs.take(id, PENDING, RUNNING, "east", AT, AT.plusSeconds(60));

        assertThat(runs.lapsed(RUNNING, AT.plusSeconds(30))).doesNotContain(id);
        assertThat(runs.failLapsed(id, RUNNING, "failed", "executor_lost", "gone", AT.plusSeconds(30))).isZero();
        assertThat(finish(id, "west")).as("another executor's finish writes nothing").isZero();

        assertThat(runs.lapsed(RUNNING, AT.plusSeconds(61))).containsExactly(id);
        assertThat(runs.failLapsed(id, RUNNING, "failed", "executor_lost", "gone", AT.plusSeconds(61))).isOne();
        assertThat(finish(id, "east")).as("the owner that came back after its lease writes nothing either").isZero();

        ReportRunEntity failed = runs.findById(id).orElseThrow();
        assertThat(failed.getState()).isEqualTo("failed");
        assertThat(failed.getReason()).isEqualTo("executor_lost");
        assertThat(failed.getActiveKey()).isNull();
        assertThat(failed.getClaimedBy()).isNull();
        assertThat(runs.existsByActiveKey(ReportRunService.activeKey("summary", 1))).isFalse();

        long next = run(1, PENDING, ReportRunService.activeKey("summary", 1), AT.plusSeconds(90)).getId();
        runs.take(next, PENDING, RUNNING, "east", AT, AT.plusSeconds(600));
        assertThat(finish(next, "east")).isOne();
        ReportRunEntity produced = runs.findById(next).orElseThrow();
        assertThat(produced.getState()).isEqualTo("produced");
        assertThat(produced.getExportSha256()).isEqualTo("e".repeat(64));
        assertThat(produced.getSignerIdentity()).hasSize(500);
        assertThat(produced.getOutputMediaType()).hasSize(120);
        assertThat(produced.getSigningKeyId()).isEqualTo("k".repeat(64));
        assertThat(produced.getPackageSha256()).isEqualTo("p".repeat(64));
        assertThat(produced.getActiveKey()).isNull();
    }

    private int finish(long id, String owner) {
        return runs.finish(id, RUNNING, owner, "produced", null, null, AT.plusSeconds(120), "Checkout", AT.plusSeconds(100),
                "d".repeat(64), "sha256:" + "a".repeat(64), "i".repeat(500), "https://issuer.example", null, "1.0",
                "e".repeat(64), 12L, 0, 34L, "f".repeat(64), "0.9.0", "m".repeat(120), "k".repeat(64), "p".repeat(64));
    }

    @Test
    @DisplayName("an export's bytes come back whole, and go by age and with their project's runs")
    void exportsKeptAndPurged() {
        long kept = run(1, ReportRunState.PRODUCED.wireName(), null, AT).getId();
        long old = run(1, ReportRunState.PRODUCED.wireName(), null, AT).getId();
        long other = run(2, ReportRunState.PRODUCED.wireName(), null, AT).getId();
        byte[] content = new byte[3 * 1024 * 1024];
        Arrays.fill(content, (byte) '{');
        export(kept, content, AT);
        export(old, new byte[] {'{', '}'}, AT.minusSeconds(86_400));
        export(other, new byte[] {'[', ']'}, AT);

        assertThat(exports.findById(kept).orElseThrow().getContent()).isEqualTo(content);
        assertThat(exports.deleteCreatedBefore(AT.minusSeconds(3600))).isOne();
        assertThat(exports.existsById(old)).isFalse();
        assertThat(runs.existsById(old)).as("the run and its digests stay").isTrue();

        assertThat(exports.deleteByProject(1)).isOne();
        assertThat(runs.deleteByProject(1)).isEqualTo(2);
        assertThat(exports.existsById(other)).isTrue();
        assertThat(runs.existsById(other)).isTrue();
    }

    @Test
    @DisplayName("an export at the run's bound is kept whole; on MySQL's default packet that bound is below 64 MiB")
    void exportAtTheBound() {
        long standard = ProjectExportBounds.STANDARD.maxJsonBytes();
        long bound = ceiling.bounds().maxJsonBytes();
        if (ENGINE == Engine.MYSQL) {
            // Half the default 64 MiB packet, less the margin: what Connector/J's hex encoding leaves.
            assertThat(bound).isLessThan(standard).isGreaterThan(30L * 1024 * 1024);
        } else {
            assertThat(bound).isEqualTo(standard);
        }

        long kept = run(1, ReportRunState.PRODUCED.wireName(), null, AT).getId();
        byte[] content = jsonShaped(bound);
        export(kept, content, AT);
        assertThat(exports.findById(kept).orElseThrow().getContent()).isEqualTo(content);

        if (ENGINE == Engine.MYSQL) {
            // Why the bound is lower there: the standard size is a statement the default server refuses — a run that
            // produced it would have dropped its document at the write.
            long refused = run(2, ReportRunState.PRODUCED.wireName(), null, AT).getId();
            byte[] whole = jsonShaped(standard);
            assertThatThrownBy(() -> export(refused, whole, AT)).hasStackTraceContaining("max_allowed_packet");
            assertThat(exports.existsById(refused)).isFalse();
        }
    }

    /** {@code size} bytes of JSON-like text, quotes and backslashes included — what a driver may escape. */
    private static byte[] jsonShaped(long size) {
        byte[] pattern = "{\"title\":\"a \\\"quoted\\\" line\\n\"},".getBytes(StandardCharsets.UTF_8);
        byte[] content = new byte[Math.toIntExact(size)];
        for (int i = 0; i < content.length; i++) {
            content[i] = pattern[i % pattern.length];
        }
        return content;
    }

    @Test
    @DisplayName("a document's bytes come back whole, and go by age and with their project's runs")
    void documentsKeptAndPurged() {
        long kept = run(1, ReportRunState.PRODUCED.wireName(), null, AT).getId();
        long old = run(1, ReportRunState.PRODUCED.wireName(), null, AT).getId();
        long other = run(2, ReportRunState.PRODUCED.wireName(), null, AT).getId();
        // Larger than a MySQL blob's 64 KiB and a medium blob's 16 MiB: the column must hold an output at its ceiling.
        byte[] content = new byte[20 * 1024 * 1024];
        Arrays.fill(content, (byte) 'P');
        document(kept, content, AT);
        document(old, new byte[] {'P', 'K'}, AT.minusSeconds(86_400));
        document(other, new byte[] {'P', 'K'}, AT);

        assertThat(documents.findById(kept).orElseThrow().getContent()).isEqualTo(content);
        assertThat(documents.deleteCreatedBefore(AT.minusSeconds(3600))).isOne();
        assertThat(documents.existsById(old)).isFalse();
        assertThat(runs.existsById(old)).as("the run and its digests stay").isTrue();

        assertThat(documents.deleteByProject(1)).isOne();
        assertThat(documents.existsById(other)).isTrue();
    }

    private void document(long runId, byte[] content, Instant at) {
        ReportDocumentEntity document = new ReportDocumentEntity();
        document.setRunId(runId);
        document.setContent(content);
        document.setSha256("0".repeat(64));
        document.setSizeBytes((long) content.length);
        document.setCreatedAt(at);
        documents.saveAndFlush(document);
    }

    private void export(long runId, byte[] content, Instant at) {
        ReportExportEntity export = new ReportExportEntity();
        export.setRunId(runId);
        export.setContent(content);
        export.setSha256("0".repeat(64));
        export.setSizeBytes((long) content.length);
        export.setCreatedAt(at);
        exports.saveAndFlush(export);
    }
}
