package com.asmolabs.vectispire.core.exports;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.VexJustification;
import com.asmolabs.vectispire.common.domain.vex.OpenVexDocument;
import com.asmolabs.vectispire.common.domain.vex.OpenVexStatement;
import com.asmolabs.vectispire.common.domain.vex.VexStatus;
import com.asmolabs.vectispire.core.issues.IssueCatalog;
import com.asmolabs.vectispire.core.issues.IssueView;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueFilters;
import com.asmolabs.vectispire.core.scanning.ScanCatalog;
import com.asmolabs.vectispire.core.scanning.ScanDocumentService;
import com.asmolabs.vectispire.core.scanning.ScanFindingView;
import com.asmolabs.vectispire.core.scanning.ScanView;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * Generates OpenVEX v0.2.0 documents from scan findings and triage decisions.
 *
 * <p><b>Reachability is not read.</b> A finding or an issue reading {@code REACHABLE} was stated
 * {@code affected} with "active invocation in call path" and its traces — a claim about the call
 * graph in a document handed to customers. Nothing computes that column, so the sentence was never
 * true when written, and every other statement said it was "awaiting reachability confirmation",
 * a confirmation nothing would ever give.
 */
@Service
public class VexGeneratorService {

    private final ScanCatalog scansRepo;
    private final ScanDocumentService documents;
    private final IssueCatalog issuesRepo;

    public VexGeneratorService(ScanCatalog scansRepo, ScanDocumentService documents, IssueCatalog issuesRepo) {
        this.scansRepo = scansRepo;
        this.documents = documents;
        this.issuesRepo = issuesRepo;
    }

    /**
     * The statements of a scan the caller may see, refused as {@code CycloneDxGeneratorService}'s
     * document is: here, in {@code scanning}'s words, absent and hidden alike.
     *
     * @throws com.asmolabs.vectispire.common.domain.errors.NotFoundException "Scan not found."
     */
    public Optional<OpenVexDocument> generateForScan(long scanId, Visibility allowed) {
        documents.requireVisible(scanId, allowed);
        return scansRepo.scan(scanId).map(this::buildVexForScan);
    }

    public OpenVexDocument generateAggregate(Visibility allowed) {
        List<IssueView> issues = issuesRepo.issues(withCve(allowed));
        List<OpenVexStatement> statements = new ArrayList<>();

        for (IssueView issue : issues) {
            if (issue.identifier() == null || !issue.identifier().toUpperCase(Locale.ROOT).startsWith("CVE-")) {
                continue;
            }
            statements.add(createStatementFromIssue(issue));
        }

        return OpenVexDocument.create(
                "https://vectispire.internal/api/v1/vex/aggregate/openvex.json",
                Instant.now(),
                statements);
    }

    private OpenVexDocument buildVexForScan(ScanView scan) {
        List<ScanFindingView> scanFindings = scansRepo.findings(scan.id());
        List<OpenVexStatement> statements = new ArrayList<>();

        for (ScanFindingView finding : scanFindings) {
            String identifier = finding.identifier();
            if (identifier == null || !identifier.toUpperCase(Locale.ROOT).startsWith("CVE-")) {
                continue;
            }
            statements.add(createStatementFromFinding(finding));
        }

        String uri = "https://vectispire.internal/api/v1/vex/scans/" + scan.id() + "/openvex.json";
        return OpenVexDocument.create(uri, scan.createdAt() != null ? scan.createdAt() : Instant.now(), statements);
    }

    private OpenVexStatement createStatementFromFinding(ScanFindingView finding) {
        String cve = finding.identifier();
        String purl = finding.purl() != null && !finding.purl().isBlank()
                ? finding.purl()
                : "pkg:generic/" + (finding.packageName() != null ? finding.packageName() : "unknown") + "@" + (finding.packageVersion() != null ? finding.packageVersion() : "latest");

        // No `not_affected` from a finding: clearing a component is a person's triage, which a
        // finding does not carry — see the issue-level statement below.
        return new OpenVexStatement(
                Map.of("name", cve),
                List.of(OpenVexStatement.Product.of(purl)),
                VexStatus.UNDER_INVESTIGATION,
                null,
                null,
                "Awaiting contextual triage.",
                null,
                null);
    }

    private OpenVexStatement createStatementFromIssue(IssueView issue) {
        String cve = issue.identifier();
        String purl = issue.purl() != null && !issue.purl().isBlank()
                ? issue.purl()
                : "pkg:generic/" + (issue.packageName() != null ? issue.packageName() : "unknown") + "@" + (issue.packageVersion() != null ? issue.packageVersion() : "latest");

        if ("closed".equalsIgnoreCase(issue.state()) || "resolved".equalsIgnoreCase(issue.state())) {
            return OpenVexStatement.fixed(cve, purl, "Remediated and verified resolved.");
        }

        if ("false_positive".equalsIgnoreCase(issue.triageStatus()) || "accepted_risk".equalsIgnoreCase(issue.triageStatus())) {
            String justification = issue.triageJustification() != null ? issue.triageJustification() : "Accepted under documented security exception.";
            return OpenVexStatement.notAffected(cve, purl, VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST, justification);
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
    private static IssueFilters withCve(Visibility allowed) {
        return new IssueFilters(null, null, null, null, null, null, false, false, null, allowed).onlyCves();
    }

}
