package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.RemediationSla;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.remediation.RemediationDistribution;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.repositories.IssueAggregates;
import com.asmolabs.vectispire.core.repositories.IssueFilters;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.services.issues.SlaService;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The remediation figures a process obligation actually asks for.
 *
 * <p><b>What this replaces is a mean.</b> The summary already reports a mean time to remediate,
 * and a mean is dragged by the volume of easy fixes: two hundred low findings closed in a day put
 * it at a day, while a critical sits open for eight months without moving it. Both numbers are
 * true; only one describes the process.
 *
 * <p>Two reads, shaped differently because they answer differently. Resolutions are rows over a
 * window — percentiles need the values, and the window is what bounds the read. The open backlog
 * is a {@code group by}: how many, how many overdue, and the oldest, none of which needs a row.
 *
 * <p><b>Open items are deliberately not windowed.</b> An issue open for eight months is the point
 * of the measurement, and a ninety-day window is precisely the filter that would hide it.
 */
@Service
public class RemediationDistributionService {

    /** Ninety days: long enough for a quarterly review, short enough to describe the present. */
    public static final int DEFAULT_WINDOW_DAYS = 90;

    public static final int MAX_WINDOW_DAYS = 365;

    private final Issues issues;
    private final SlaService sla;
    private final Clock clock;

    public RemediationDistributionService(Issues issues, SlaService sla, Clock clock) {
        this.issues = issues;
        this.sla = sla;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public RemediationDistribution distribution(int requestedDays, Visibility allowed) {
        int windowDays = Math.clamp(requestedDays, 7, MAX_WINDOW_DAYS);
        Instant since = clock.instant().minus(Duration.ofDays(windowDays));
        RemediationSla policy = sla.policy();

        Specification<IssueEntity> visible =
                new IssueFilters(null, null, null, null, null, null, false, false, null, allowed)
                        .toSpecification();

        List<RemediationDistribution.Resolved> resolved =
                issues.resolvedDurationsSince(visible, since).stream()
                        .map(row -> new RemediationDistribution.Resolved(
                                Severity.of(row.severity()), row.seconds()))
                        .toList();

        Instant now = clock.instant();
        Map<Severity, Instant> thresholds = policy.overdueThresholds(now);

        List<RemediationDistribution.Open> open = new ArrayList<>();
        for (IssueAggregates.OpenBacklog row : issues.openBacklogBySeverity(visible)) {
            Severity severity = Severity.of(row.severity());
            if (severity == Severity.UNKNOWN || row.oldestFirstSeen() == null) {
                // An unrecognised severity has no deadline to be late against, and putting it in
                // a per-severity table would invent a row nobody's policy describes.
                continue;
            }
            open.add(new RemediationDistribution.Open(
                    severity,
                    row.total(),
                    countOverdue(severity, thresholds, allowed),
                    Duration.between(row.oldestFirstSeen(), now).toDays()));
        }

        return RemediationDistribution.calculate(windowDays, policy, resolved, open);
    }

    /**
     * How many of one severity's open issues are past their deadline.
     *
     * <p><b>Counted through {@link SlaService}, and with the caller's visibility.</b> The service
     * owns the thresholds and the "settled issues are not late" rule; a second implementation
     * here would be a second answer, and the one on a dashboard would be the one nobody
     * reconciles against the list it links to. The first draft of this method reached for
     * {@code Visibility.EVERYTHING} instead of the caller's, which is the defect this codebase
     * has shipped more often than any other.
     */
    private long countOverdue(Severity severity, Map<Severity, Instant> thresholds, Visibility allowed) {
        Instant threshold = thresholds.get(severity);
        if (threshold == null) {
            // No window for this severity: nothing can be late against a deadline nobody set.
            return 0;
        }
        return issues.count(sla.overdue(Map.of(severity, threshold), allowed).toSpecification());
    }

}
