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

    public record ComplianceSummary(
            List<ComplianceEvaluation> evaluations,
            MttrCalculator.MttrResult mttr,
            long overdueCount,
            long dueSoonCount,
            int totalMonitoredTargets,
            int passingGateTargets) {}

    @Transactional(readOnly = true)
    public ComplianceSummary getSummary(Visibility allowed) {
        SecurityOverview.Overview posture = gate.overview(allowed);
        int totalTargets = posture.totalCount();
        int passingTargets = totalTargets - posture.failingCount();

        long critical = countOpen(Severity.CRITICAL, null, allowed);
        long high = countOpen(Severity.HIGH, null, allowed);
        long medium = countOpen(Severity.MEDIUM, null, allowed);
        long low = countOpen(Severity.LOW, null, allowed);
        long kev = countOpen(null, true, allowed);
        long overdue = sla.countOverdue(allowed);
        long secrets = issues.count(new IssueFilters(IssueState.OPEN.wireName(), null, FindingType.SECRET.wireName(), null, null, null, false, false, null, true, Map.of(), allowed).toSpecification());
        long sast = issues.count(new IssueFilters(IssueState.OPEN.wireName(), null, FindingType.QUALITY.wireName(), null, null, null, false, false, null, true, Map.of(), allowed).toSpecification());
        long iac = issues.count(new IssueFilters(IssueState.OPEN.wireName(), null, FindingType.IAC.wireName(), null, null, null, false, false, null, true, Map.of(), allowed).toSpecification());

        int withSbom = (int) scans.findAll().stream()
                .filter(s -> s.getSbom() != null && !s.getSbom().isBlank())
                .map(s -> s.getRepoId() != null ? "repo:" + s.getRepoId() : "container:" + s.getContainerId())
                .distinct()
                .count();

        boolean auditValid = audit.verify().broken() == null;

        ComplianceEngine.PostureInput input = new ComplianceEngine.PostureInput(
                totalTargets,
                totalTargets - (int) posture.neverScannedCount(),
                passingTargets,
                critical, high, medium, low, kev, overdue, secrets, sast, iac,
                Math.min(totalTargets, withSbom),
                auditValid);

        List<ComplianceEvaluation> evaluations = ComplianceEngine.evaluateAll(input);

        // MTTR calculation over resolved issues
        List<MttrCalculator.ResolvedIssue> resolved = issues.findAll(new IssueFilters(IssueState.RESOLVED.wireName(), null, null, null, null, null, false, false, null, allowed).toSpecification())
                .stream()
                .map(i -> new MttrCalculator.ResolvedIssue(Severity.of(i.getSeverity()), i.getFirstSeenAt(), i.getResolvedAt()))
                .toList();

        MttrCalculator.MttrResult mttr = MttrCalculator.calculate(resolved);

        return new ComplianceSummary(evaluations, mttr, overdue, 0L, totalTargets, passingTargets);
    }

    @Transactional(readOnly = true)
    public ComplianceEvaluation getEvaluation(ComplianceFramework framework, Visibility allowed) {
        ComplianceSummary summary = getSummary(allowed);
        return summary.evaluations().stream()
                .filter(e -> e.framework() == framework)
                .findFirst()
                .orElseGet(() -> ComplianceEngine.evaluate(framework, new ComplianceEngine.PostureInput(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, true)));
    }

    private long countOpen(Severity severity, Boolean isKev, Visibility allowed) {
        return issues.count(new IssueFilters(
                IssueState.OPEN.wireName(),
                severity == null ? null : severity.wireName(),
                null,
                null,
                null,
                null,
                false,
                isKev != null && isKev,
                null,
                true,
                Map.of(),
                allowed).toSpecification());
    }
}
