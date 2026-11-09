package com.asmolabs.vectispire.core.threatintel.web;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.threatintel.EpssRiskMatrix.EpssFleetSummary;
import com.asmolabs.vectispire.common.domain.threatintel.EpssRiskMatrix.EpssPrioritizedIssue;
import com.asmolabs.vectispire.common.domain.threatintel.EpssRiskMatrix.RecommendedAction;
import java.lang.reflect.RecordComponent;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The view that carries the EPSS ranking onto the wire, held to the domain records it copies.
 *
 * <p>It exists for three annotations — the scores may be null — and a copy drifts: a field added to
 * {@link EpssPrioritizedIssue} or {@link EpssFleetSummary} and not to the view would vanish from the
 * response without an error anywhere.
 */
@DisplayName("the EPSS ranking's wire view")
class EpssFleetSummaryViewTest {

    @Test
    @DisplayName("has the components of the domain records, in their order")
    void mirrors_the_domain() {
        assertThat(names(EpssFleetSummaryView.class)).isEqualTo(names(EpssFleetSummary.class));
        assertThat(names(EpssFleetSummaryView.EpssPrioritizedIssueView.class))
                .isEqualTo(names(EpssPrioritizedIssue.class));
    }

    @Test
    @DisplayName("copies every value, an issue nobody scored included")
    void copies_every_value() {
        EpssPrioritizedIssue unscored = new EpssPrioritizedIssue(7L, "CVE-2026-1", "openssl", "high", null, null,
                null, false, "corp/ledger", "REPOSITORY", 40, "LOW_PROBABILITY", RecommendedAction.P3_ROUTINE);
        EpssPrioritizedIssue scored = new EpssPrioritizedIssue(8L, "CVE-2026-2", "log4j", "critical", 9.8, 0.9,
                0.99, true, "shop:1.4.2", "CONTAINER", 100, "CRITICAL_ARMED", RecommendedAction.P0_KEV_24H);
        EpssFleetSummary summary =
                new EpssFleetSummary(2, 1, 1, 0.9, List.of(unscored, scored), Map.of("CRITICAL_ARMED", 1));

        EpssFleetSummaryView view = EpssFleetSummaryView.of(summary);

        assertThat(values(view).subList(0, 4)).isEqualTo(values(summary).subList(0, 4));
        assertThat(view.breakdownByTier()).isEqualTo(summary.breakdownByTier());
        assertThat(view.topPriorities().stream().map(EpssFleetSummaryViewTest::values).toList())
                .isEqualTo(summary.topPriorities().stream().map(EpssFleetSummaryViewTest::values).toList());
    }

    private static List<String> names(Class<?> record) {
        return Arrays.stream(record.getRecordComponents()).map(RecordComponent::getName).toList();
    }

    private static List<Object> values(Record record) {
        return Arrays.stream(record.getClass().getRecordComponents())
                .map(component -> {
                    try {
                        return component.getAccessor().invoke(record);
                    } catch (ReflectiveOperationException unreadable) {
                        throw new IllegalStateException(unreadable);
                    }
                })
                .toList();
    }
}
