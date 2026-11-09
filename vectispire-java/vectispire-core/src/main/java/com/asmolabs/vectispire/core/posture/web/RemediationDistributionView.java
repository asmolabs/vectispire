package com.asmolabs.vectispire.core.posture.web;

import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.remediation.RemediationDistribution;
import com.asmolabs.vectispire.core.gate.ViolationView;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

/**
 * The remediation distribution, as the wire spells it.
 *
 * <h2>One difference from the domain record, and it cost a test</h2>
 *
 * <p><b>Severity in lowercase.</b> The domain carries the {@link Severity} enum, ordered worst
 * first, which is what makes it comparable. Serialised as it stands it goes out as
 * {@code CRITICAL} — while every other route in this API passes through
 * {@link Severity#wireName()} and sends {@code critical}. This route was the only one deciding
 * otherwise, and nothing said so.
 *
 * <p>A client branching on severity therefore had to know two spellings. The screen's test looked
 * for {@code severity === 'low'} and found no row; its fixture wrote {@code 'low'} as well, so the
 * absence never threw and the test stayed green. <b>Two errors that agree make a test that measures
 * nothing.</b>
 *
 * <h2>Why not {@code @JsonValue} on the enum</h2>
 *
 * <p>It would have fixed both fields at once, and a great deal more: Jackson applies
 * {@code @JsonValue} to map <em>keys</em>, and {@code countsBySeverity} and
 * {@code backlogBySeverity} are maps. The screens index them by {@code ['CRITICAL']}. The most
 * elegant fix broke the dashboard — checked before it was set aside, not after.
 *
 * <h2>Why a view rather than an annotation on the record</h2>
 *
 * <p>{@code vectispire-common} is the domain module and depends on no web annotation: putting
 * {@code @Schema} there would have let springdoc into a layer that does not want it.
 * {@link ViolationView} exists for exactly this reason, and says exactly that.
 *
 * <p>The list of values is copied into {@code @Schema} because an accessor returning a
 * {@code String} leaves nothing to enumerate. A copied list drifts:
 * {@code RemediationSeverityWireTest} is what stops it, comparing what the document publishes to
 * {@code Severity.values()}.
 */
public record RemediationDistributionView(
        int windowDays, List<BySeverityView> bySeverity, Long oldestOpenDays, String oldestOpenSeverity) {

    /** The six values of {@link Severity}, in the form this API uses everywhere. */
    static final String[] WIRE_SEVERITIES = {"critical", "high", "medium", "low", "negligible", "unknown"};

    public static RemediationDistributionView of(RemediationDistribution distribution) {
        return new RemediationDistributionView(
                distribution.windowDays(),
                distribution.bySeverity().stream().map(BySeverityView::of).toList(),
                distribution.oldestOpenDays(),
                wire(distribution.oldestOpenSeverity()));
    }

    private static String wire(Severity severity) {
        return severity == null ? null : severity.wireName();
    }

    /** @see RemediationDistribution.BySeverity */
    public record BySeverityView(
            @Schema(allowableValues = {"critical", "high", "medium", "low", "negligible", "unknown"})
                    String severity,
            int windowDays,
            long withinSla,
            long late,
            Double percentageWithinSla,
            Double medianDays,
            Double ninetiethDays,
            long openOverdue,
            Long oldestOpenDays) {

        static BySeverityView of(RemediationDistribution.BySeverity row) {
            return new BySeverityView(
                    wire(row.severity()),
                    row.windowDays(),
                    row.withinSla(),
                    row.late(),
                    row.percentageWithinSla(),
                    row.medianDays(),
                    row.ninetiethDays(),
                    row.openOverdue(),
                    row.oldestOpenDays());
        }
    }

    /** The same enumeration as above, on the top-level field. */
    @Schema(allowableValues = {"critical", "high", "medium", "low", "negligible", "unknown"})
    @Override
    public String oldestOpenSeverity() {
        return oldestOpenSeverity;
    }
}
