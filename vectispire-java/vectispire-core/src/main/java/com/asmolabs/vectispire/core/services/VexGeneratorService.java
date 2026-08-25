package com.asmolabs.vectispire.core.services;

import com.asmolabs.vectispire.common.domain.reachability.ReachabilityStatus;
import com.asmolabs.vectispire.common.domain.vex.OpenVexDocument;
import com.asmolabs.vectispire.common.domain.vex.OpenVexStatement;
import com.asmolabs.vectispire.common.domain.vex.VexJustification;
import com.asmolabs.vectispire.common.domain.vex.VexStatus;
import com.asmolabs.vectispire.core.persistence.FindingEntity;
import com.asmolabs.vectispire.core.persistence.IssueEntity;
import com.asmolabs.vectispire.core.persistence.ScanEntity;
import com.asmolabs.vectispire.core.repositories.Findings;
import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.core.repositories.IssueFilters;
import org.springframework.data.jpa.domain.Specification;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.repositories.Scans;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * Generates OpenVEX v0.2.0 documents from scan findings, reachability traces, and triage decisions.
 */
@Service
public class VexGeneratorService {

    private final Scans scansRepo;
    private final Findings findingsRepo;
    private final Issues issuesRepo;

    public VexGeneratorService(Scans scansRepo, Findings findingsRepo, Issues issuesRepo) {
        this.scansRepo = scansRepo;
        this.findingsRepo = findingsRepo;
        this.issuesRepo = issuesRepo;
    }

    public Optional<OpenVexDocument> generateForScan(Long scanId) {
        return scansRepo.findById(scanId).map(this::buildVexForScan);
    }

    public OpenVexDocument generateAggregate(Visibility allowed) {
        List<IssueEntity> issues = issuesRepo.findAll(withCve(allowed));
        List<OpenVexStatement> statements = new ArrayList<>();

        for (IssueEntity issue : issues) {
            if (issue.getIdentifier() == null || !issue.getIdentifier().toUpperCase().startsWith("CVE-")) {
                continue;
            }
            statements.add(createStatementFromIssue(issue));
        }

        return OpenVexDocument.create(
                "https://vectispire.internal/api/v1/vex/aggregate/openvex.json",
                Instant.now(),
                statements);
    }

    private OpenVexDocument buildVexForScan(ScanEntity scan) {
        List<FindingEntity> scanFindings = findingsRepo.findByScanId(scan.getId());
        List<OpenVexStatement> statements = new ArrayList<>();

        for (FindingEntity finding : scanFindings) {
            String identifier = finding.getIdentifier();
            if (identifier == null || !identifier.toUpperCase().startsWith("CVE-")) {
                continue;
            }
            statements.add(createStatementFromFinding(finding));
        }

        String uri = "https://vectispire.internal/api/v1/vex/scans/" + scan.getId() + "/openvex.json";
        return OpenVexDocument.create(uri, scan.getCreatedAt() != null ? scan.getCreatedAt() : Instant.now(), statements);
    }

    private OpenVexStatement createStatementFromFinding(FindingEntity finding) {
        String cve = finding.getIdentifier();
        String purl = finding.getPurl() != null && !finding.getPurl().isBlank()
                ? finding.getPurl()
                : "pkg:generic/" + (finding.getPackageName() != null ? finding.getPackageName() : "unknown") + "@" + (finding.getPackageVersion() != null ? finding.getPackageVersion() : "latest");

        String reachability = finding.getReachability();
        if (ReachabilityStatus.UNREACHABLE.name().equalsIgnoreCase(reachability)) {
            return OpenVexStatement.notAffected(
                    cve,
                    purl,
                    VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
                    "Vectispire static analysis verified no direct call path invokes the vulnerable code.");
        }

        if (ReachabilityStatus.REACHABLE.name().equalsIgnoreCase(reachability)) {
            String traces = finding.getReachableSymbols() != null ? " Traces: " + finding.getReachableSymbols() : "";
            return OpenVexStatement.affected(
                    cve,
                    purl,
                    "Active invocation in call path." + traces + " Upgrade or apply security patch.");
        }

        return new OpenVexStatement(
                Map.of("name", cve),
                List.of(purl),
                VexStatus.UNDER_INVESTIGATION,
                null,
                null,
                "Awaiting reachability confirmation and contextual triage.",
                null);
    }

    private OpenVexStatement createStatementFromIssue(IssueEntity issue) {
        String cve = issue.getIdentifier();
        String purl = issue.getPurl() != null && !issue.getPurl().isBlank()
                ? issue.getPurl()
                : "pkg:generic/" + (issue.getPackageName() != null ? issue.getPackageName() : "unknown") + "@" + (issue.getPackageVersion() != null ? issue.getPackageVersion() : "latest");

        if ("closed".equalsIgnoreCase(issue.getState()) || "resolved".equalsIgnoreCase(issue.getState())) {
            return OpenVexStatement.fixed(cve, purl, "Remediated and verified resolved.");
        }

        if ("false_positive".equalsIgnoreCase(issue.getTriageStatus()) || "accepted_risk".equalsIgnoreCase(issue.getTriageStatus())) {
            String justification = issue.getTriageJustification() != null ? issue.getTriageJustification() : "Accepted under documented security exception.";
            return OpenVexStatement.notAffected(cve, purl, VexJustification.INLINE_MITIGATIONS_EXIST, justification);
        }

        if (ReachabilityStatus.UNREACHABLE.name().equalsIgnoreCase(issue.getReachability())) {
            return OpenVexStatement.notAffected(
                    cve,
                    purl,
                    VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
                    "Vectispire static analysis verified no direct call path invokes the vulnerable code.");
        }

        if (ReachabilityStatus.REACHABLE.name().equalsIgnoreCase(issue.getReachability())) {
            return OpenVexStatement.affected(
                    cve,
                    purl,
                    "Active invocation in call path. Remediation prioritized under SLA.");
        }

        return OpenVexStatement.affected(
                cve,
                purl,
                "Open issue awaiting remediation.");
    }

    /**
     * The issues this document is built from: those carrying a CVE, within the caller's allowance.
     *
     * <p><b>Two defects in one line.</b> The read was {@code findAll()} — every issue in the
     * deployment, with the CVE test applied afterwards in Java — and it carried no
     * {@link Visibility} at all, so an aggregate export handed a restricted reader the
     * identifiers, packages and versions of every target they had not been given.
     *
     * <p>The allowance is expressed through {@link IssueFilters}, which is where the
     * authorization predicate already lives. Restating it here would be a second copy of a rule
     * that must not have two.
     */
    private static Specification<IssueEntity> withCve(Visibility allowed) {
        return new IssueFilters(null, null, null, null, null, null, false, false, null, allowed)
                .toSpecification()
                .and((root, query, builder) ->
                        builder.like(builder.upper(root.get("identifier")), "CVE-%"));
    }

}
