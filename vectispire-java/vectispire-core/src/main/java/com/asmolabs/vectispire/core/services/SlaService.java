package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.RemediationSla;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.repositories.IssueFilters;
import com.asmolabs.vectispire.core.repositories.Issues;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.EnumMap;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The remediation policy, read from the settings and applied.
 *
 * <p>The rule itself is {@link RemediationSla}, which is pure and exhaustively tested. This class
 * only does the two things a domain object cannot: read the four windows out of the settings
 * table, and count how many issues are past theirs without loading the backlog to find out.
 */
@Service
public class SlaService {

    private final SettingsService settings;
    private final Issues issues;
    private final Clock clock;

    public SlaService(SettingsService settings, Issues issues, Clock clock) {
        this.settings = settings;
        this.issues = issues;
        this.clock = clock;
    }

    /**
     * The configured policy.
     *
     * <p>Read per call rather than cached: a window is changed on the settings screen and the
     * next page load has to show the consequence, or somebody will conclude the setting does
     * nothing. Four reads from a table of a few dozen rows.
     */
    public RemediationSla policy() {
        Map<Severity, Duration> windows = new EnumMap<>(Severity.class);
        windows.put(Severity.CRITICAL, Duration.ofDays(settings.asInt(Setting.SLA_CRITICAL_DAYS)));
        windows.put(Severity.HIGH, Duration.ofDays(settings.asInt(Setting.SLA_HIGH_DAYS)));
        windows.put(Severity.MEDIUM, Duration.ofDays(settings.asInt(Setting.SLA_MEDIUM_DAYS)));
        windows.put(Severity.LOW, Duration.ofDays(settings.asInt(Setting.SLA_LOW_DAYS)));
        // The record's constructor drops the zeroes: "no deadline at this severity" is expressed
        // by absence, not by a zero-length window that would read as "due immediately".
        return new RemediationSla(windows);
    }

    /** Where one issue stands, or empty when no deadline applies to it. */
    public Optional<RemediationSla.Assessment> assess(RemediationSla policy, IssueEntity issue) {
        return policy.assess(
                Severity.of(issue.getSeverity()),
                issue.getFirstSeenAt(),
                IssueState.OPEN.wireName().equals(issue.getState()),
                TriageStatus.fromWireName(issue.getTriageStatus()).map(TriageStatus::isSettled).orElse(false),
                clock.instant());
    }

    /**
     * The overdue count for every target at once.
     *
     * <p><b>One read for a page of targets.</b> The compliance summary asked this per row, which
     * is the shape that turns one page into hundreds of round trips on a real estate. The rows
     * are loaded rather than counted per group because the windows are per-severity instants,
     * and expressing that as a grouped aggregate would put the policy into the query; the set is
     * bounded by the number of *breaches*, which is small by construction — an estate where it
     * is not has a problem this figure is meant to reveal.
     *
     * <p>Keyed as {@code repo:<id>} / {@code container:<id>}, the key the summary already uses.
     */
    public java.util.Map<String, Long> countOverdueByTarget(Visibility allowed) {
        Map<Severity, Instant> thresholds = policy().overdueThresholds(clock.instant());
        if (thresholds.isEmpty()) {
            // Same reasoning as countOverdue: an empty `or (…)` has two readings and neither is
            // safe to guess.
            return java.util.Map.of();
        }

        java.util.Map<String, Long> perTarget = new java.util.HashMap<>();
        // **Two columns.** This groups overdue issues by the target they belong to and reads
        // nothing else off them, so loading entities cost one managed object per overdue issue in
        // the estate — the same shape as the four reads `ReadCostRoutesTest` pins, and the one
        // that kept the compliance summary linear after the other four were projected.
        for (com.asmolabs.vectispire.core.repositories.IssueRows.Attribution row : issues.findBy(
                overdue(thresholds, allowed).toSpecification(),
                query -> query.as(com.asmolabs.vectispire.core.repositories.IssueRows.Attribution.class).all())) {
            Long repoId = row.repoId();
            Long containerId = row.containerId();
            if (repoId == null && containerId == null) {
                continue;
            }
            perTarget.merge(repoId != null ? "repo:" + repoId : "container:" + containerId, 1L, Long::sum);
        }
        return perTarget;
    }

    /**
     * How many open issues are past their window, within what the caller may see.
     *
     * <p><b>Counted in the database, one severity at a time.</b> Assessing every row would mean
     * reading the whole backlog to produce a single number on a dashboard — and the comparison
     * each severity needs is exactly {@code first_seen_at < now - window}, which an index
     * answers. Four counts, and only for the severities that have a window at all.
     *
     * <p><b>Narrowed by visibility, like every other read.</b> A figure counting targets the
     * caller cannot open would tell them how much they are not being shown, which is both a leak
     * and a number they can do nothing with.
     */
    @Transactional(readOnly = true)
    public long countOverdue(Visibility allowed) {
        Map<Severity, Instant> thresholds = policy().overdueThresholds(clock.instant());
        if (thresholds.isEmpty()) {
            // Every window disabled. Asking anyway would build an empty `or (…)`, whose two
            // possible readings — false, or true — are the difference between "none late" and
            // "all late".
            return 0;
        }
        return issues.count(overdue(thresholds, allowed).toSpecification());
    }

    /**
     * The filter behind both the figure and the list.
     *
     * <p>Exposed rather than duplicated in the controller: a count and a list built from two
     * copies of the same clause disagree the first time one of them is edited, and the
     * disagreement reads as a bug in the count.
     */
    public IssueFilters overdue(Map<Severity, Instant> thresholds, Visibility allowed) {
        return new IssueFilters(
                IssueState.OPEN.wireName(),
                null,
                null,
                null,
                null,
                null,
                false,
                false,
                null,
                // Settled issues excluded in the clause rather than filtered afterwards: a triage
                // decision is not lateness, and the count and the rows must agree on that.
                true,
                thresholds,
                allowed);
    }

    /** The thresholds now, for a caller that needs them to build its own narrower filter. */
    public Map<Severity, Instant> overdueThresholds() {
        return policy().overdueThresholds(clock.instant());
    }
}
