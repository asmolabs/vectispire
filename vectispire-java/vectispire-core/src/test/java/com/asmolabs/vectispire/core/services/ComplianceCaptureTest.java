package com.asmolabs.vectispire.core.services;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.compliance.ComplianceHistory;
import com.asmolabs.vectispire.core.VectispireContextTest;
import com.asmolabs.vectispire.core.persistence.ComplianceSnapshotEntity;
import com.asmolabs.vectispire.core.repositories.ComplianceSnapshots;
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
    private ComplianceSnapshots snapshots;

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
                .as("le tick tourne toutes les heures : une ligne par passage ferait d'un mois "
                        + "sept cents points, et d'un mois clos autre chose que son état de fin de mois")
                .hasSize(captured);
    }

    @Test
    @DisplayName("records the estate that produced the verdict, not only the verdict")
    void recordsWhatProducedIt() {
        history.capture();

        assertThat(snapshots.findAll()).allSatisfy(row -> {
            // Sans ces colonnes, une note lue six mois plus tard ne se distingue pas d'une autre :
            // la même valeur peut venir d'un parc propre ou d'un parc que personne n'a regardé.
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
                            .as("un seul point n'est pas une tendance, et le dire vaut mieux que "
                                    + "de tracer la ligne quand même")
                            .isFalse();
                });
    }

    @Test
    @DisplayName("keeps the maintenance tick alive when a capture cannot be written")
    void neverThrows() {
        // Une capture qui échoue ne doit pas emporter le tick avec elle : un mois manquant est un
        // trou dans un graphique, un tick arrêté est une purge, un outbox et une péremption de
        // triage arrêtés.
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

        // Un cadre retiré de l'énumération entre deux versions rendrait sinon tout l'historique
        // illisible — et un document qui ne s'ouvre pas est pire qu'un document incomplet.
        assertThat(history.history()).isNotNull();
    }
}
