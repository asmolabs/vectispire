package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceEngine;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceEvaluation;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceFramework;
import com.asmolabs.vectispire.common.domain.gate.SecurityOverview;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
import com.asmolabs.vectispire.common.domain.settings.Setting;
import com.asmolabs.vectispire.common.domain.trends.MttrCalculator;
import com.asmolabs.vectispire.core.repositories.Containers;
import com.asmolabs.vectispire.core.repositories.GitRepositories;
import com.asmolabs.vectispire.core.repositories.IssueFilters;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Service aggregating compliance evaluations and MTTR / SLA analytics.
 */
@Service
public class ComplianceService {

    private final GateService gate;
    private final Issues issues;
    private final Scans scans;
    private final GitRepositories repositories;
    private final Containers containers;
    private final SlaService sla;
    private final AuditLogService audit;
    private final EncryptionService encryption;
    private final SettingsService settings;

    public ComplianceService(
            GateService gate,
            Issues issues,
            Scans scans,
            GitRepositories repositories,
            Containers containers,
            SlaService sla,
            AuditLogService audit,
            EncryptionService encryption,
            SettingsService settings) {
        this.gate = gate;
        this.issues = issues;
        this.scans = scans;
        this.repositories = repositories;
        this.containers = containers;
        this.sla = sla;
        this.audit = audit;
        this.encryption = encryption;
        this.settings = settings;
    }

    /**
     * The open-issue counts for every target, read in one query.
     *
     * <p>Replaces nine counts per target inside the loop below. The rows carry
     * {@code [repoId, containerId, severity, type, isKev, count]}; one pass over them fills every
     * axis the summary reports, because a row contributes to its severity, its type <em>and</em>
     * the KEV tally at once.
     *
     * <p>Visibility is applied by the caller, not by the query: the loop iterates the
     * already-filtered target list and looks each one up here, so a group belonging to a target
     * the caller cannot see is never read. That equivalence holds because issue visibility is
     * target-scoped and nothing else — see {@code IssueFilters}.
     */
    private record TargetCounts(
            long critical, long high, long medium, long low, long kev,
            long secrets, long sast, long iac) {

        static final TargetCounts NONE = new TargetCounts(0, 0, 0, 0, 0, 0, 0, 0);

        TargetCounts plus(String severity, String type, boolean isKev, long n) {
            Severity parsed = Severity.of(severity);
            return new TargetCounts(
                    critical + (parsed == Severity.CRITICAL ? n : 0),
                    high + (parsed == Severity.HIGH ? n : 0),
                    medium + (parsed == Severity.MEDIUM ? n : 0),
                    low + (parsed == Severity.LOW ? n : 0),
                    kev + (isKev ? n : 0),
                    secrets + (FindingType.SECRET.wireName().equals(type) ? n : 0),
                    // `QUALITY`, not `SAST`: what the summary has always counted here, kept as
                    // it was rather than corrected in a change about query shape.
                    sast + (FindingType.QUALITY.wireName().equals(type) ? n : 0),
                    iac + (FindingType.IAC.wireName().equals(type) ? n : 0));
        }

        long total() {
            return critical + high + medium + low;
        }
    }

    /** Keyed the way the loop below identifies a target: repository id, or container id. */
    private static String targetKey(Long repoId, Long containerId) {
        return repoId != null ? "repo:" + repoId : "container:" + containerId;
    }

    private Map<String, TargetCounts> openCountsByTarget() {
        Map<String, TargetCounts> counts = new java.util.HashMap<>();
        for (Object[] row : issues.countOpenGroupedByTarget(IssueState.OPEN.wireName())) {
            Long repoId = (Long) row[0];
            Long containerId = (Long) row[1];
            if (repoId == null && containerId == null) {
                continue;
            }
            String key = targetKey(repoId, containerId);
            counts.merge(
                    key,
                    TargetCounts.NONE.plus((String) row[2], (String) row[3], toBoolean(row[4]), ((Number) row[5]).longValue()),
                    (a, b) -> new TargetCounts(
                            a.critical() + b.critical(), a.high() + b.high(), a.medium() + b.medium(),
                            a.low() + b.low(), a.kev() + b.kev(), a.secrets() + b.secrets(),
                            a.sast() + b.sast(), a.iac() + b.iac()));
        }
        return counts;
    }

    /**
     * Tolerant of a numeric flag, though no engine currently sends one.
     *
     * <p>Written on the assumption that SQLite would hand back an Integer where the others hand
     * back a Boolean. **Measured afterwards, and that is not what happens**: the projection
     * selects a mapped entity attribute, so Hibernate normalises it to {@code Boolean} on every
     * engine the campaign runs — replacing this with a plain cast passes everywhere.
     *
     * <p>Kept anyway, and the reason is narrow rather than superstitious: the day this projection
     * reads a column the entity does not map, the normalisation goes with it. The comment is
     * corrected rather than the code, because a defence whose stated reason is false is worse
     * than no defence — somebody will trust the reason.
     */
    private static boolean toBoolean(Object value) {
        return value instanceof Boolean flag ? flag : value instanceof Number n && n.intValue() != 0;
    }

    /**
     * What this deployment has switched on, read fresh on every evaluation.
     *
     * <p>Not cached: these are settings an administrator changes, and a compliance report built
     * from a cached copy of them would be a report about a configuration that no longer exists.
     * All three are cheap — two field reads and one settings lookup.
     */
    private ComplianceEngine.PlatformPosture platformPosture() {
        // `mirrorConfigured()` and not `verifyAgainstMirror()`: the latter reads the entire
        // mirror file and every audit row to compare them, and this runs on every compliance
        // page load. What the control needs to know is whether a second copy exists, not
        // whether it currently agrees — that is `/audit-log/verify`, which somebody asks for.
        return new ComplianceEngine.PlatformPosture(
                encryption.isConfigured(),
                encryption.isExternallyManaged(),
                audit.mirrorConfigured(),
                settings.isEnabled(Setting.FOUR_EYES_APPROVAL_REQUIRED));
    }

    public record TargetCompliance(
            String targetId,
            String name,
            String type,
            String gateStatus,
            long openIssuesCount,
            long overdueCount,
            int overallScore,
            String overallStatus,
            Map<String, Integer> frameworkScores) {}

    public record ComplianceSummary(
            List<ComplianceEvaluation> evaluations,
            MttrCalculator.MttrResult mttr,
            long overdueCount,
            long dueSoonCount,
            int totalMonitoredTargets,
            int passingGateTargets,
            List<TargetCompliance> targets) {
        public ComplianceSummary(
                List<ComplianceEvaluation> evaluations,
                MttrCalculator.MttrResult mttr,
                long overdueCount,
                long dueSoonCount,
                int totalMonitoredTargets,
                int passingGateTargets) {
            this(evaluations, mttr, overdueCount, dueSoonCount, totalMonitoredTargets, passingGateTargets, List.of());
        }
    }

    @Transactional(readOnly = true)
    public ComplianceSummary getSummary(Visibility allowed) {
        return getSummary(null, allowed);
    }

    @Transactional(readOnly = true)
    public ComplianceSummary getSummary(String targetId, Visibility allowed) {
        SecurityOverview.Overview posture = gate.overview(allowed);

        if (targetId != null && !targetId.isBlank()
                && !"ALL".equalsIgnoreCase(targetId)
                && !"null".equalsIgnoreCase(targetId)
                && !"undefined".equalsIgnoreCase(targetId)) {
            return getSummaryForTarget(targetId, posture, allowed);
        }

        return getGlobalSummary(posture, allowed);
    }

    private ComplianceSummary getGlobalSummary(SecurityOverview.Overview posture, Visibility allowed) {
        int totalTargets = posture.totalCount();
        int observedTargets = (int) posture.targets().stream().filter(SecurityOverview.TargetPosture::observed).count();
        int passingTargets = (int) posture.targets().stream().filter(p -> p.observed() && p.passed()).count();

        long critical = countOpen(Severity.CRITICAL, null, null, null, allowed);
        long high = countOpen(Severity.HIGH, null, null, null, allowed);
        long medium = countOpen(Severity.MEDIUM, null, null, null, allowed);
        long low = countOpen(Severity.LOW, null, null, null, allowed);
        long kev = countOpen(null, true, null, null, allowed);
        long overdue = sla.countOverdue(allowed);
        long secrets = countOpenType(FindingType.SECRET, null, null, allowed);
        long sast = countOpenType(FindingType.QUALITY, null, null, allowed);
        long iac = countOpenType(FindingType.IAC, null, null, allowed);

        // **Bounded, and not the full verification.** `verify()` reads every audit row and says
        // of itself that it is not for a page render; this checks that the recent entries still
        // match their own hashes, which is the modification case. Deletion detection stays with
        // /audit-log/verify and the mirror — and the compliance control already reports the
        // mirror's absence, so the reader is not left thinking otherwise.
        boolean auditValid = audit.recentEntriesMatchTheirHashes();
        ComplianceEngine.PlatformPosture platform = platformPosture();

        // **Two queries for the whole page, not nine per target.** Both are read before the
        // per-target loop below; see `openCountsByTarget` for why applying visibility in the
        // loop rather than in the query is equivalent.
        Map<String, TargetCounts> counts = openCountsByTarget();
        Map<String, Long> overdueByTarget = sla.countOverdueByTarget(allowed);

        ComplianceEngine.PostureInput input = new ComplianceEngine.PostureInput(
                Math.max(1, totalTargets),
                observedTargets,
                passingTargets,
                critical, high, medium, low, kev, overdue, secrets, sast, iac,
                observedTargets,
                auditValid);

        List<ComplianceEvaluation> evaluations = ComplianceEngine.evaluateAll(input, platform);

        // MTTR calculation over resolved issues
        List<MttrCalculator.ResolvedIssue> resolved = issues.findAll(new IssueFilters(IssueState.RESOLVED.wireName(), null, null, null, null, null, false, false, null, allowed).toSpecification())
                .stream()
                .map(i -> new MttrCalculator.ResolvedIssue(Severity.of(i.getSeverity()), i.getFirstSeenAt(), i.getResolvedAt()))
                .toList();

        MttrCalculator.MttrResult mttr = MttrCalculator.calculate(resolved);

        // Per-target compliance matrix
        List<TargetCompliance> targetComplianceList = posture.targets().stream().map(targetPosture -> {
            Long repoId = targetPosture.target() instanceof com.asmolabs.vectispire.common.domain.targets.ScanTarget.Repository r ? r.id() : null;
            Long containerId = targetPosture.target() instanceof com.asmolabs.vectispire.common.domain.targets.ScanTarget.Container c ? c.id() : null;
            String tid = (repoId != null ? "repo:" + repoId : "container:" + containerId);
            String type = (repoId != null ? "REPOSITORY" : "CONTAINER");

            // Read from the two grouped queries taken before the loop, not asked per target.
            // `tid` is the same key `openCountsByTarget` builds, and a target with no open issue
            // simply has no group.
            TargetCounts tCounts = counts.getOrDefault(tid, TargetCounts.NONE);
            long tCrit = tCounts.critical();
            long tHigh = tCounts.high();
            long tMed = tCounts.medium();
            long tLow = tCounts.low();
            long tKev = tCounts.kev();
            long tOverdue = overdueByTarget.getOrDefault(tid, 0L);
            long tSec = tCounts.secrets();
            long tSast = tCounts.sast();
            long tIac = tCounts.iac();

            long totalOpen = tCounts.total();

            boolean isObserved = targetPosture.observed();
            boolean isPassed = targetPosture.observed() && targetPosture.passed();

            ComplianceEngine.PostureInput tInput = new ComplianceEngine.PostureInput(
                    1,
                    isObserved ? 1 : 0,
                    isPassed ? 1 : 0,
                    tCrit, tHigh, tMed, tLow, tKev, tOverdue, tSec, tSast, tIac,
                    isObserved ? 1 : 0,
                    auditValid);

            List<ComplianceEvaluation> tEvals = ComplianceEngine.evaluateAll(tInput, platform);
            Map<String, Integer> scores = new java.util.HashMap<>();
            tEvals.forEach(e -> scores.put(e.framework().name(), e.scorePercentage()));

            int avgScore = (int) Math.round(tEvals.stream().mapToInt(ComplianceEvaluation::scorePercentage).average().orElse(100.0));
            String status = avgScore == 100 ? "COMPLIANT" : (avgScore >= 70 ? "PARTIAL" : "NON_COMPLIANT");
            
            String gateStatus;
            if (targetPosture.observation() == SecurityOverview.Observation.IN_PROGRESS) {
                gateStatus = "SCANNING";
            } else if (targetPosture.observation() == SecurityOverview.Observation.NEVER_SCANNED) {
                gateStatus = "NEVER_SCANNED";
            } else if (targetPosture.observation() == SecurityOverview.Observation.LAST_SCAN_FAILED) {
                gateStatus = "FAILED";
            } else {
                gateStatus = targetPosture.passed() ? "PASSED" : "FAILED";
            }

            return new TargetCompliance(tid, targetPosture.name(), type, gateStatus, totalOpen, tOverdue, avgScore, status, scores);
        }).toList();

        return new ComplianceSummary(evaluations, mttr, overdue, 0L, totalTargets, passingTargets, targetComplianceList);
    }

    private ComplianceSummary getSummaryForTarget(String targetId, SecurityOverview.Overview posture, Visibility allowed) {
        Long repoId = null;
        Long containerId = null;

        if (targetId.startsWith("repo:") || targetId.startsWith("repository:")) {
            repoId = Long.parseLong(targetId.substring(targetId.indexOf(':') + 1));
        } else if (targetId.startsWith("container:")) {
            containerId = Long.parseLong(targetId.substring(targetId.indexOf(':') + 1));
        }

        final Long fRepoId = repoId;
        final Long fContainerId = containerId;

        SecurityOverview.TargetPosture targetPosture = posture.targets().stream()
                .filter(p -> {
                    if (fRepoId != null && p.target() instanceof com.asmolabs.vectispire.common.domain.targets.ScanTarget.Repository r) {
                        return r.id() == fRepoId;
                    }
                    if (fContainerId != null && p.target() instanceof com.asmolabs.vectispire.common.domain.targets.ScanTarget.Container c) {
                        return c.id() == fContainerId;
                    }
                    return false;
                })
                .findFirst()
                .orElse(null);

        int totalTargets = 1;
        boolean observed = targetPosture != null && targetPosture.observed();
        int passingTargets = (targetPosture != null && targetPosture.observed() && targetPosture.passed()) ? 1 : 0;

        long critical = countOpen(Severity.CRITICAL, null, repoId, containerId, allowed);
        long high = countOpen(Severity.HIGH, null, repoId, containerId, allowed);
        long medium = countOpen(Severity.MEDIUM, null, repoId, containerId, allowed);
        long low = countOpen(Severity.LOW, null, repoId, containerId, allowed);
        long kev = countOpen(null, true, repoId, containerId, allowed);
        long overdue = countOverdueForTarget(repoId, containerId, allowed);
        long secrets = countOpenType(FindingType.SECRET, repoId, containerId, allowed);
        long sast = countOpenType(FindingType.QUALITY, repoId, containerId, allowed);
        long iac = countOpenType(FindingType.IAC, repoId, containerId, allowed);

        // **Bounded, and not the full verification.** `verify()` reads every audit row and says
        // of itself that it is not for a page render; this checks that the recent entries still
        // match their own hashes, which is the modification case. Deletion detection stays with
        // /audit-log/verify and the mirror — and the compliance control already reports the
        // mirror's absence, so the reader is not left thinking otherwise.
        boolean auditValid = audit.recentEntriesMatchTheirHashes();
        ComplianceEngine.PlatformPosture platform = platformPosture();

        // **Two queries for the whole page, not nine per target.** Both are read before the
        // per-target loop below; see `openCountsByTarget` for why applying visibility in the
        // loop rather than in the query is equivalent.
        Map<String, TargetCounts> counts = openCountsByTarget();
        Map<String, Long> overdueByTarget = sla.countOverdueByTarget(allowed);

        ComplianceEngine.PostureInput input = new ComplianceEngine.PostureInput(
                totalTargets,
                observed ? 1 : 0,
                passingTargets,
                critical, high, medium, low, kev, overdue, secrets, sast, iac,
                observed ? 1 : 0,
                auditValid);

        List<ComplianceEvaluation> evaluations = ComplianceEngine.evaluateAll(input, platform);

        List<MttrCalculator.ResolvedIssue> resolved = issues.findAll(new IssueFilters(
                IssueState.RESOLVED.wireName(), null, null, null, repoId, containerId, false, false, null, allowed).toSpecification())
                .stream()
                .map(i -> new MttrCalculator.ResolvedIssue(Severity.of(i.getSeverity()), i.getFirstSeenAt(), i.getResolvedAt()))
                .toList();

        MttrCalculator.MttrResult mttr = MttrCalculator.calculate(resolved);

        // Build targetComplianceList as well so table never disappears
        List<TargetCompliance> targetComplianceList = posture.targets().stream().map(tp -> {
            Long rId = tp.target() instanceof com.asmolabs.vectispire.common.domain.targets.ScanTarget.Repository r ? r.id() : null;
            Long cId = tp.target() instanceof com.asmolabs.vectispire.common.domain.targets.ScanTarget.Container c ? c.id() : null;
            String tid = (rId != null ? "repo:" + rId : "container:" + cId);
            String type = (rId != null ? "REPOSITORY" : "CONTAINER");

            // Same two grouped reads as the other summary: one lookup, no query per target.
            TargetCounts tCounts = counts.getOrDefault(tid, TargetCounts.NONE);
            long tCrit = tCounts.critical();
            long tHigh = tCounts.high();
            long tMed = tCounts.medium();
            long tLow = tCounts.low();
            long tKev = tCounts.kev();
            long tOverdue = overdueByTarget.getOrDefault(tid, 0L);
            long tSec = tCounts.secrets();
            long tSast = tCounts.sast();
            long tIac = tCounts.iac();

            long totalOpen = tCounts.total();
            boolean isObs = tp.observed();
            boolean isPass = tp.observed() && tp.passed();

            ComplianceEngine.PostureInput tInput = new ComplianceEngine.PostureInput(
                    1,
                    isObs ? 1 : 0,
                    isPass ? 1 : 0,
                    tCrit, tHigh, tMed, tLow, tKev, tOverdue, tSec, tSast, tIac,
                    isObs ? 1 : 0,
                    auditValid);

            List<ComplianceEvaluation> tEvals = ComplianceEngine.evaluateAll(tInput, platform);
            Map<String, Integer> scores = new java.util.HashMap<>();
            tEvals.forEach(e -> scores.put(e.framework().name(), e.scorePercentage()));

            int avgScore = (int) Math.round(tEvals.stream().mapToInt(ComplianceEvaluation::scorePercentage).average().orElse(100.0));
            String status = avgScore == 100 ? "COMPLIANT" : (avgScore >= 70 ? "PARTIAL" : "NON_COMPLIANT");
            
            String gateStatus;
            if (tp.observation() == SecurityOverview.Observation.IN_PROGRESS) {
                gateStatus = "SCANNING";
            } else if (tp.observation() == SecurityOverview.Observation.NEVER_SCANNED) {
                gateStatus = "NEVER_SCANNED";
            } else if (tp.observation() == SecurityOverview.Observation.LAST_SCAN_FAILED) {
                gateStatus = "FAILED";
            } else {
                gateStatus = tp.passed() ? "PASSED" : "FAILED";
            }

            return new TargetCompliance(tid, tp.name(), type, gateStatus, totalOpen, tOverdue, avgScore, status, scores);
        }).toList();

        return new ComplianceSummary(evaluations, mttr, overdue, 0L, totalTargets, passingTargets, targetComplianceList);
    }

    @Transactional(readOnly = true)
    public ComplianceEvaluation getEvaluation(ComplianceFramework framework, Visibility allowed) {
        ComplianceSummary summary = getSummary(allowed);
        return summary.evaluations().stream()
                .filter(e -> e.framework() == framework)
                .findFirst()
                .orElseGet(() -> ComplianceEngine.evaluate(
                        framework,
                        new ComplianceEngine.PostureInput(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, true),
                        platformPosture()));
    }

    private long countOpen(Severity severity, Boolean isKev, Long repoId, Long containerId, Visibility allowed) {
        return issues.count(new IssueFilters(
                IssueState.OPEN.wireName(),
                severity == null ? null : severity.wireName(),
                null,
                null,
                repoId,
                containerId,
                false,
                isKev != null && isKev,
                null,
                true,
                Map.of(),
                allowed).toSpecification());
    }

    private long countOpenType(FindingType type, Long repoId, Long containerId, Visibility allowed) {
        return issues.count(new IssueFilters(
                IssueState.OPEN.wireName(),
                null,
                type.wireName(),
                null,
                repoId,
                containerId,
                false,
                false,
                null,
                true,
                Map.of(),
                allowed).toSpecification());
    }

    private long countOverdueForTarget(Long repoId, Long containerId, Visibility allowed) {
        Map<Severity, Instant> thresholds = sla.overdueThresholds();
        if (thresholds.isEmpty()) {
            return 0;
        }
        return issues.count(new IssueFilters(
                IssueState.OPEN.wireName(),
                null,
                null,
                null,
                repoId,
                containerId,
                false,
                false,
                null,
                true,
                thresholds,
                allowed).toSpecification());
    }
}
