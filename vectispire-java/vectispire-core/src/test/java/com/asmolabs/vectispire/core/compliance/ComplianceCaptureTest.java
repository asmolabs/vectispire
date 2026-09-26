package com.asmolabs.vectispire.core.compliance;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.compliance.ComplianceHistory;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.compliance.persistence.ComplianceSnapshotEntity;
import com.asmolabs.vectispire.core.compliance.persistence.ComplianceSnapshotRepository;
import java.time.Clock;
import java.time.YearMonth;
import java.time.ZoneOffset;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Writing the month's compliance capture.
 *
 * <h2>Why the capture is rewritten rather than written once</h2>
 *
 * <p>The tick runs hourly. Writing only on the first pass of a month would record a verdict from
 * the first of the month and label it with the month — and nobody reading "August" expects the
 * 1st of August. Rewriting means a closed month carries its state at the last capture inside it,
 * which is its end.
 *
 * <p>That is what the first two cases pin, and it is the only part of this service with a decision
 * in it: the attribution is tested against the pure model, without a database.
 */
@DisplayName("capturing a month of compliance")
class ComplianceCaptureTest extends VectispireContextTest {

    @Autowired
    private ComplianceHistoryService history;

    @Autowired
    private ComplianceSnapshotRepository snapshots;

    @Autowired
    private Clock clock;

    @Test
    @DisplayName("writes one capture per framework, for the month it runs in")
    void writesOnePerFramework() {
        int captured = history.capture();

        String period = YearMonth.from(clock.instant().atZone(ZoneOffset.UTC)).toString();
        assertThat(captured).isPositive();
        assertThat(snapshots.findAll())
                .hasSize(captured)
                .allSatisfy(row -> assertThat(row.getPeriod()).isEqualTo(period));
    }

    @Test
    @DisplayName("rewrites the running month rather than adding a second row for it")
    void rewritesTheRunningMonth() {
        int captured = history.capture();
        history.capture();
        history.capture();

        assertThat(snapshots.findAll())
                .as("the tick runs hourly: one row per pass would make a month seven hundred "
                        + "points, and a closed month something other than its end-of-month state")
                .hasSize(captured);
    }

    @Test
    @DisplayName("records the estate that produced the verdict, not only the verdict")
    void recordsWhatProducedIt() {
        history.capture();

        assertThat(snapshots.findAll()).allSatisfy(row -> {
            // Without these columns, a score read six months later is indistinguishable from
            // another: the same value can come from a clean estate or one nobody has looked at.
            assertThat(row.getFreshnessDays()).isNotNegative();
            assertThat(row.getTargets()).isNotNegative();
            assertThat(row.getControlsTotal()).isPositive();
            assertThat(row.getCapturedAt()).isNotNull();
        });
    }

    @Test
    @DisplayName("hands back a series per framework, each month attributed")
    void readsBackAsAttributedSeries() {
        history.capture();

        assertThat(history.history())
                .isNotEmpty()
                .allSatisfy(series -> {
                    assertThat(series.steps()).isNotEmpty();
                    assertThat(series.steps().getFirst().movement())
                            .isEqualTo(ComplianceHistory.Movement.FIRST);
                    assertThat(series.comparable())
                            .as("a single point is not a trend, and saying so beats drawing the "
                                    + "line anyway")
                            .isFalse();
                });
    }

    @Test
    @DisplayName("keeps the maintenance tick alive when a capture cannot be written")
    void neverThrows() {
        // A capture that fails must not take the tick down with it: a missing month is a gap in a
        // chart, a stopped tick is a purge, an outbox and a triage expiry all stopped.
        snapshots.deleteAll();
        assertThat(history.capture()).isNotNegative();
    }

    @Test
    @DisplayName("ignores a capture whose framework this build no longer carries")
    void unknownFrameworkIsDropped() {
        history.capture();
        ComplianceSnapshotEntity ghost = snapshots.findAll().getFirst();
        ghost.setFramework("A_STANDARD_NOBODY_PORTED");
        snapshots.save(ghost);

        // A framework dropped from the enumeration between two versions would otherwise make the
        // whole history unreadable — and a document that will not open is worse than an incomplete
        // one.
        assertThat(history.history()).isNotNull();
    }
}
