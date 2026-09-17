package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceControl;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceEvaluation;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceFramework;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceHistory;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceSnapshot;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.SoaStatement;
import com.asmolabs.vectispire.common.domain.rules.RuleCoverage;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.core.persistence.ComplianceSnapshotEntity;
import com.asmolabs.vectispire.core.repositories.ComplianceSnapshots;
import java.time.Clock;
import java.time.Instant;
import java.time.YearMonth;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Captures the compliance verdict month by month, and reads the progression back.
 *
 * <h2>Why a capture rather than a query over the past</h2>
 *
 * <p>The reasoning is on {@link ComplianceSnapshot}: a verdict depends on settings and on code
 * that both move, so the past cannot be recomputed without rewriting it. What is here is the
 * mechanics — and two decisions worth stating.
 *
 * <p><b>The current month is rewritten on every pass.</b> A month therefore carries its state at
 * the last capture inside it, which for a closed month is its end. The alternative — writing once
 * at the first pass of the month — would record a verdict from the first of the month and call it
 * the month's, which is the more surprising of the two behaviours.
 *
 * <p><b>The capture is of the whole estate, never of a reader's slice.</b> A history narrowed per
 * reader would give each of them a different past, and none of them an audit trail. The route that
 * reads it is gated on the role instead.
 */
@Service
public class ComplianceHistoryService {

    private static final Logger log = LoggerFactory.getLogger(ComplianceHistoryService.class);

    private final ComplianceSnapshots snapshots;
    private final ComplianceService compliance;
    private final StatementOfApplicabilityService soa;
    private final RuleCoverageService ruleCoverage;
    private final SettingsService settings;
    private final Clock clock;

    public ComplianceHistoryService(
            ComplianceSnapshots snapshots,
            ComplianceService compliance,
            StatementOfApplicabilityService soa,
            RuleCoverageService ruleCoverage,
            SettingsService settings,
            Clock clock) {
        this.snapshots = snapshots;
        this.compliance = compliance;
        this.soa = soa;
        this.ruleCoverage = ruleCoverage;
        this.settings = settings;
        this.clock = clock;
    }

    /**
     * Writes this month's capture for every framework.
     *
     * <p>Never throws: a capture that fails must not take the maintenance tick with it. A missing
     * month is a hole in a chart; a tick that stops is a purge that stops, an outbox that stops
     * and a triage expiry that stops.
     *
     * @return how many frameworks were captured
     */
    @Transactional
    public int capture() {
        try {
            String period = YearMonth.from(clock.instant().atZone(ZoneOffset.UTC)).toString();
            Instant now = clock.instant();

            var summary = compliance.getSummary(Visibility.everything());
            int freshnessDays = Math.max(0, settings.asInt(Setting.COMPLIANCE_FRESHNESS_DAYS));
            boolean codeAnalysisReaches = settings.isEnabled(Setting.SAST_ENABLED)
                    && ruleCoverage.assess().state() != RuleCoverage.State.UNCONFIGURED;
            boolean eol = settings.isEnabled(Setting.EOL_ENABLED);

            int captured = 0;
            for (ComplianceEvaluation evaluation : summary.evaluations()) {
                SoaStatement statement = soa.statement(evaluation.framework(), Visibility.everything());
                write(period, now, evaluation, summary.totalMonitoredTargets(),
                        summary.observedTargets(), summary.freshTargets(),
                        freshnessDays, eol, codeAnalysisReaches, statement);
                captured++;
            }
            return captured;
        } catch (RuntimeException failed) {
            log.warn("Compliance capture skipped: {}", failed.getMessage());
            return 0;
        }
    }

    private void write(
            String period,
            Instant now,
            ComplianceEvaluation evaluation,
            int targets,
            int observed,
            int fresh,
            int freshnessDays,
            boolean eol,
            boolean codeAnalysisReaches,
            SoaStatement statement) {

        ComplianceSnapshotEntity row = snapshots
                .findByPeriodAndFramework(period, evaluation.framework().name())
                .orElseGet(() -> {
                    ComplianceSnapshotEntity created = new ComplianceSnapshotEntity();
                    created.setId(UUID.randomUUID());
                    created.setPeriod(period);
                    created.setFramework(evaluation.framework().name());
                    return created;
                });

        row.setScore(evaluation.scorePercentage());
        row.setStatus(evaluation.overallStatus().name());
        row.setTargets(targets);
        row.setObservedTargets(observed);
        // **Both come from the summary and are not recounted here.** They are exactly the numbers
        // that capped the verdicts above; recomputing them alongside would produce a second answer
        // to the same question, and it is the second that would never be reconciled.
        row.setFreshTargets(fresh);
        row.setFreshnessDays(freshnessDays);
        row.setEndOfLifeEnabled(eol);
        row.setCodeAnalysisReaches(codeAnalysisReaches);
        row.setControlsTotal(statement.total());
        row.setControlsDeclared(statement.declared());
        row.setSoaFindings(statement.findings());
        row.setCapturedAt(now);

        snapshots.save(row);
    }

    /** Every framework's progression, each month attributed to what plausibly moved it. */
    @Transactional(readOnly = true)
    public List<ComplianceHistory.Series> history() {
        List<ComplianceSnapshot> all = snapshots.findAllOrdered().stream()
                .map(ComplianceHistoryService::toDomain)
                .filter(java.util.Objects::nonNull)
                .toList();

        List<ComplianceHistory.Series> series = new ArrayList<>();
        for (ComplianceFramework framework : ComplianceFramework.values()) {
            ComplianceHistory.Series one = ComplianceHistory.of(framework, all);
            if (!one.steps().isEmpty()) {
                series.add(one);
            }
        }
        return List.copyOf(series);
    }

    /** Null for a row whose framework this build no longer carries — see the same rule on the SoA. */
    private static ComplianceSnapshot toDomain(ComplianceSnapshotEntity row) {
        ComplianceFramework framework;
        try {
            framework = ComplianceFramework.valueOf(row.getFramework());
        } catch (IllegalArgumentException unknown) {
            return null;
        }
        return new ComplianceSnapshot(
                row.getPeriod(),
                framework,
                row.getScore(),
                ComplianceControl.Status.valueOf(row.getStatus()),
                row.getTargets(),
                row.getObservedTargets(),
                row.getFreshTargets(),
                row.getFreshnessDays(),
                row.isEndOfLifeEnabled(),
                row.isCodeAnalysisReaches(),
                row.getControlsTotal(),
                row.getControlsDeclared(),
                row.getSoaFindings(),
                row.getCapturedAt());
    }
}
