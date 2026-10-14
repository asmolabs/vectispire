package com.asmolabs.vectispire.core.posture.web;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.remediation.HighImpactFix;
import com.asmolabs.vectispire.common.domain.remediation.SecurityDebtReport;
import java.lang.reflect.RecordComponent;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The view that carries the security debt report onto the wire, held to the domain records it copies.
 *
 * <p>It exists for one annotation — {@code recommendedVersion} may be null — and a copy drifts: a
 * field added to {@link HighImpactFix} or {@link SecurityDebtReport} and not to the view would vanish
 * from the response without an error anywhere.
 */
@DisplayName("the security debt report's wire view")
class SecurityDebtReportViewTest {

    @Test
    @DisplayName("has the components of the domain records, in their order")
    void mirrors_the_domain() {
        assertThat(names(SecurityDebtReportView.class)).isEqualTo(names(SecurityDebtReport.class));
        assertThat(names(SecurityDebtReportView.HighImpactFixView.class)).isEqualTo(names(HighImpactFix.class));
    }

    @Test
    @DisplayName("copies every value, a fix with no published version included")
    void copies_every_value() {
        HighImpactFix unfixed = new HighImpactFix(
                "openssl", "3.0.1", null, 2, 0, 1, 2.5, 0.8, List.of("CVE-2026-1234"), List.of("Arm Libs Spring"));
        HighImpactFix fixed = new HighImpactFix(
                "log4j-core", "2.14.1", "2.17.1", 4, 1, 2, 3.0, 1.6, List.of("CVE-2021-44228"), List.of("api"));
        SecurityDebtReport report =
                new SecurityDebtReport(6, 1, 3, 1, 1, 5.5, 0.7, 5.5, 0, 0, 0, 0, 0, List.of(unfixed, fixed));

        SecurityDebtReportView view = SecurityDebtReportView.of(report);

        // Every figure but the last component, the list, which is compared fix by fix below.
        assertThat(values(view).subList(0, 13)).isEqualTo(values(report).subList(0, 13));
        assertThat(view.topHighImpactFixes()).extracting(SecurityDebtReportView.HighImpactFixView::recommendedVersion)
                .containsExactly(null, "2.17.1");
        assertThat(view.topHighImpactFixes().stream().map(SecurityDebtReportViewTest::values).toList())
                .isEqualTo(report.topHighImpactFixes().stream().map(SecurityDebtReportViewTest::values).toList());
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
