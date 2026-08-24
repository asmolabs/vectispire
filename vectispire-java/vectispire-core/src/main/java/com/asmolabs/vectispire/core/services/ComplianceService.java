package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceEngine;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceEvaluation;
import com.asmolabs.vectispire.common.domain.compliance.ComplianceFramework;
import com.asmolabs.vectispire.common.domain.gate.SecurityOverview;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.issues.Severity;
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

    public ComplianceService(
            GateService gate,
            Issues issues,
            Scans scans,
            GitRepositories repositories,
            Containers containers,
            SlaService sla,
            AuditLogService audit) {
        this.gate = gate;
        this.issues = issues;
        this.scans = scans;
        this.repositories = repositories;
        this.containers = containers;
        this.sla = sla;
        this.audit = audit;
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

        boolean auditValid = audit.verify().broken() == null;

        ComplianceEngine.PostureInput input = new ComplianceEngine.PostureInput(
                Math.max(1, totalTargets),
                observedTargets,
                passingTargets,
                critical, high, medium, low, kev, overdue, secrets, sast, iac,
                observedTargets,
                auditValid);

        List<ComplianceEvaluation> evaluations = ComplianceEngine.evaluateAll(input);

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

            long tCrit = countOpen(Severity.CRITICAL, null, repoId, containerId, allowed);
            long tHigh = countOpen(Severity.HIGH, null, repoId, containerId, allowed);
            long tMed = countOpen(Severity.MEDIUM, null, repoId, containerId, allowed);
            long tLow = countOpen(Severity.LOW, null, repoId, containerId, allowed);
            long tKev = countOpen(null, true, repoId, containerId, allowed);
            long tOverdue = countOverdueForTarget(repoId, containerId, allowed);
            long tSec = countOpenType(FindingType.SECRET, repoId, containerId, allowed);
            long tSast = countOpenType(FindingType.QUALITY, repoId, containerId, allowed);
            long tIac = countOpenType(FindingType.IAC, repoId, containerId, allowed);

            long totalOpen = tCrit + tHigh + tMed + tLow;

            boolean isObserved = targetPosture.observed();
            boolean isPassed = targetPosture.observed() && targetPosture.passed();

            ComplianceEngine.PostureInput tInput = new ComplianceEngine.PostureInput(
                    1,
                    isObserved ? 1 : 0,
                    isPassed ? 1 : 0,
                    tCrit, tHigh, tMed, tLow, tKev, tOverdue, tSec, tSast, tIac,
                    isObserved ? 1 : 0,
                    auditValid);

            List<ComplianceEvaluation> tEvals = ComplianceEngine.evaluateAll(tInput);
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

        boolean auditValid = audit.verify().broken() == null;

        ComplianceEngine.PostureInput input = new ComplianceEngine.PostureInput(
                totalTargets,
                observed ? 1 : 0,
                passingTargets,
                critical, high, medium, low, kev, overdue, secrets, sast, iac,
                observed ? 1 : 0,
                auditValid);

        List<ComplianceEvaluation> evaluations = ComplianceEngine.evaluateAll(input);

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

            long tCrit = countOpen(Severity.CRITICAL, null, rId, cId, allowed);
            long tHigh = countOpen(Severity.HIGH, null, rId, cId, allowed);
            long tMed = countOpen(Severity.MEDIUM, null, rId, cId, allowed);
            long tLow = countOpen(Severity.LOW, null, rId, cId, allowed);
            long tKev = countOpen(null, true, rId, cId, allowed);
            long tOverdue = countOverdueForTarget(rId, cId, allowed);
            long tSec = countOpenType(FindingType.SECRET, rId, cId, allowed);
            long tSast = countOpenType(FindingType.QUALITY, rId, cId, allowed);
            long tIac = countOpenType(FindingType.IAC, rId, cId, allowed);

            long totalOpen = tCrit + tHigh + tMed + tLow;
            boolean isObs = tp.observed();
            boolean isPass = tp.observed() && tp.passed();

            ComplianceEngine.PostureInput tInput = new ComplianceEngine.PostureInput(
                    1,
                    isObs ? 1 : 0,
                    isPass ? 1 : 0,
                    tCrit, tHigh, tMed, tLow, tKev, tOverdue, tSec, tSast, tIac,
                    isObs ? 1 : 0,
                    auditValid);

            List<ComplianceEvaluation> tEvals = ComplianceEngine.evaluateAll(tInput);
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
                .orElseGet(() -> ComplianceEngine.evaluate(framework, new ComplianceEngine.PostureInput(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, true)));
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
