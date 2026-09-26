package com.asmolabs.vectispire.core.compliance.web;

import com.asmolabs.vectispire.common.domain.compliance.ComplianceFramework;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.Applicability;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.Declaration;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.EvidenceSource;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.Implementation;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.SoaStatement;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
import com.asmolabs.vectispire.core.access.web.security.RequiresGovernanceRead;
import com.asmolabs.vectispire.core.access.web.security.RequiresSecurityLead;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.compliance.StatementOfApplicabilityService;
import com.asmolabs.vectispire.core.compliance.StatementOfApplicabilityService.Submission;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.time.Instant;
import java.util.List;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The declaration of applicability: what the organisation claims, set against what is measured.
 *
 * <h2>Why the product needs it</h2>
 *
 * <p><b>It is the ISO 27001 document.</b> Clause 6.1.3 d requires one — every Annex A control
 * addressed, each applicable or excluded, exclusions justified — and an assessment opens with it.
 * A tool that evaluates controls automatically and holds no declaration answers a question nobody
 * asked: it reports how things are, and the assessor came to check what was claimed against how
 * things are.
 *
 * <p>Which is where the value is. Neither half is worth much alone — a stored document nobody
 * checks, or a measurement nobody claimed anything about. <b>What an assessment turns on is the
 * line where the two disagree</b>, and a control declared implemented that the estate measures
 * non-compliant is exactly what gets written up.
 *
 * <h2>Reading and writing are different roles</h2>
 *
 * <p>Reading is governance, and anybody who may see the compliance matrix may see the declaration
 * beside it — a document read by nobody is the failure mode this feature exists to fix. Writing a
 * line is a claim recorded under somebody's name, so it needs a security lead, and it goes into
 * the audit log whichever way it went.
 */
@Tag(name = "Statement of Applicability", description = "ISO 27001 clause 6.1.3 d — what is claimed, against what is measured")
@RestController
@RequestMapping("/api/v1/compliance/soa")
@RequiresAccount
public class StatementOfApplicabilityController {

    private final StatementOfApplicabilityService soa;
    private final VisibilityService visibility;

    public StatementOfApplicabilityController(
            StatementOfApplicabilityService soa, VisibilityService visibility) {
        this.soa = soa;
        this.visibility = visibility;
    }

    /**
     * What an operator submits for one control.
     *
     * @param reviewDueAt when this line must be confirmed again; null leaves it unscheduled
     */
    public record DeclarationRequest(
            Applicability applicability,
            String justification,
            Implementation implementation,
            @JsonProperty("evidence_source") EvidenceSource evidenceSource,
            @JsonProperty("external_evidence") String externalEvidence,
            String owner,
            @JsonProperty("review_due_at") Instant reviewDueAt) {}

    @Operation(summary = "Every framework's declaration", description = "The declaration of each framework, reconciled against the caller's view of the estate.")
    @ApiResponse(responseCode = "200", description = "Statements returned")
    @GetMapping
    public List<SoaStatement> all(@AuthenticationPrincipal VectispirePrincipal principal) {
        return soa.statements(allowed(principal));
    }

    @Operation(summary = "One framework's declaration", description = "Declared and measured, line by line, with the divergence between them.")
    @ApiResponse(responseCode = "200", description = "Statement returned")
    @GetMapping("/{framework}")
    public SoaStatement one(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @PathVariable ComplianceFramework framework) {
        return soa.statement(framework, allowed(principal));
    }

    /**
     * Lines whose review has lapsed, across every framework.
     *
     * <p>Its own route rather than a filter on the statement above: "what have we stopped looking
     * at" is asked across the management system, not inside one framework, and an ISMS dashboard
     * that has to fetch six documents to assemble the answer will not ask it.
     *
     * <p><b>A role guard rather than an allowance, because there is no target to narrow.</b> A
     * declaration is a statement about the management system — "is A.8.28 applicable to us" names
     * no repository — so there is nothing for a visibility to filter, and the route would
     * otherwise disclose the governance document to any account with a session. Governance read is
     * the right lock: the set that may already inspect the compliance matrix and the audit log.
     */
    @RequiresGovernanceRead
    @Operation(summary = "Declarations due for review", description = "Lines whose review date has passed, oldest first, across every framework.")
    @ApiResponse(responseCode = "200", description = "Declarations returned")
    @GetMapping("/reviews/overdue")
    public List<Declaration> reviewOverdue() {
        return soa.reviewOverdue();
    }

    @Operation(summary = "Declare a control", description = "Writes or revises one line. An exclusion needs a justification; evidence held elsewhere must say where.")
    @ApiResponse(responseCode = "200", description = "Declaration recorded")
    @ApiResponse(responseCode = "400", description = "The line is not a declaration: an unjustified exclusion, or external evidence naming nothing")
    @ApiResponse(responseCode = "404", description = "The framework has no control of that identifier")
    @PutMapping("/{framework}/{controlId}")
    @RequiresSecurityLead
    public Declaration declare(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @PathVariable ComplianceFramework framework,
            @PathVariable String controlId,
            @RequestBody DeclarationRequest body) {

        return soa.declare(
                framework,
                controlId,
                new Submission(
                        body.applicability(),
                        body.justification(),
                        body.implementation(),
                        body.evidenceSource(),
                        body.externalEvidence(),
                        body.owner(),
                        body.reviewDueAt()),
                principal.user().map(user -> user.username()).orElse(null));
    }

    private com.asmolabs.vectispire.common.domain.access.Visibility allowed(VectispirePrincipal principal) {
        return visibility.of(principal.user().orElse(null), principal.credentialRestriction());
    }
}
