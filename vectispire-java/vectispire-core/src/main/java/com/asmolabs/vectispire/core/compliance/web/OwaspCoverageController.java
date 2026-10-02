package com.asmolabs.vectispire.core.compliance.web;

import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.Declaration;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
import com.asmolabs.vectispire.core.access.web.security.RequiresSecurityLead;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.compliance.OwaspCoverageService;
import com.asmolabs.vectispire.core.compliance.OwaspWeeklyHistoryService;
import com.asmolabs.vectispire.core.compliance.StatementOfApplicabilityService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * The Top 10, answered by rule rather than by a model.
 *
 * <h2>Why it sits beside the report and does not replace it</h2>
 *
 * <p>The report on {@code /repositories/{id}/owasp-review} is written by the configured model: it
 * reads the backlog and produces prose, which is the part a person wants and no rule engine
 * writes. <b>It is not evidence.</b> An assessor cannot accept a document whose content depends on
 * which model answered, and a category green last quarter and amber this one has told them nothing
 * about the estate.
 *
 * <p>This route answers the same ten questions from the finding's type alone. Every mapping is one
 * sentence somebody can check, every line carries why it says what it says, and where no rule
 * applies the answer is <em>not covered</em> rather than a guess.
 *
 * <h2>Three of ten, and that is the finding</h2>
 *
 * <p>Seven categories are covered by no scanner here. A grid showing them green would be claiming
 * a clean bill of health over an examination that never happened — which is the same defect the
 * freshness window removed from the compliance matrix and the banner removed from the quality
 * screen, in the one place an auditor looks first.
 */
@Tag(name = "OWASP coverage", description = "The Top 10 by rule, with what this deployment cannot see")
@RestController
@RequestMapping("/api/v1/owasp/coverage")
@RequiresAccount
public class OwaspCoverageController {

    /**
     * The key the Top 10 declarations are filed under.
     *
     * <p><b>The Top 10 does not join {@code ComplianceFramework}, and that is deliberate.</b> The
     * compliance engine does not evaluate OWASP: adding it to the enum would make it appear in
     * evaluations, summaries and the statement of applicability, where it has no business. The
     * declaration table's {@code framework} column is a free string, which is all this key needs.
     */
    static final String FRAMEWORK = "OWASP_2021";

    private final OwaspCoverageService coverage;
    private final OwaspWeeklyHistoryService weekly;
    private final VisibilityService visibility;
    private final StatementOfApplicabilityService declarations;

    public OwaspCoverageController(
            OwaspCoverageService coverage,
            OwaspWeeklyHistoryService weekly,
            VisibilityService visibility,
            StatementOfApplicabilityService declarations) {
        this.coverage = coverage;
        this.weekly = weekly;
        this.visibility = visibility;
        this.declarations = declarations;
    }

    /**
     * One row of the grid, and what the organisation states about it.
     *
     * @param declaration {@code null} when nobody has stated anything. <b>That permanent grey
     *     square is what this route exists to remove</b>: two Top 10 categories are beyond any
     *     static analysis — insecure design cannot be read out of code, and a missing log leaves,
     *     by definition, no trace. Leaving them grey is honest and carries no review; declaring
     *     them says who asserts it, on what evidence, and when it is looked at again.
     */
    public record DeclaredCoverageLine(
            String id,
            String title,
            OwaspCoverage.State state,
            long findings,
            String because,
            Declaration declaration) {

        static DeclaredCoverageLine of(OwaspCoverage.CoverageLine line, Declaration declaration) {
            return new DeclaredCoverageLine(
                    line.id(), line.title(), line.state(), line.findings(), line.because(), declaration);
        }
    }

    /** @param lines the grid in the standard's order, each row with its declaration if it has one */
    public record DeclaredGrid(List<DeclaredCoverageLine> lines, int covered, int withFindings, int unmeasured) {}

    @Operation(summary = "OWASP Top 10 coverage", description = "Each category's state — findings, nothing found, unmeasured, or covered by no scanner here.")
    @ApiResponse(responseCode = "200", description = "Grid returned")
    @GetMapping
    public DeclaredGrid grid(@AuthenticationPrincipal VectispirePrincipal principal) {
        OwaspCoverage.Grid grid = coverage.grid(
                visibility.of(principal.user().orElse(null), principal.credentialRestriction()));

        Map<String, Declaration> byCategory = declarations.declarations(FRAMEWORK).stream()
                .collect(Collectors.toMap(Declaration::controlId, Function.identity()));

        return new DeclaredGrid(
                grid.lines().stream()
                        .map(line -> DeclaredCoverageLine.of(line, byCategory.get(line.id())))
                        .toList(),
                grid.covered(),
                grid.withFindings(),
                grid.unmeasured());
    }

    /**
     * The grid week by week — the heatmap's columns and the flow bars beneath them. The rules, the
     * refusals included, are {@link OwaspWeeklyHistoryService}'s; the route maps the query string and the
     * caller.
     *
     * <p><b>Who reads it is who reads the grid</b>: a signed-in account, over what it may see. No
     * integration key, as for the grid — the record of an estate's coverage over a year is a screen's,
     * and a pipeline that needs the current state has the gate.
     */
    @Operation(summary = "OWASP Top 10 coverage, week by week", description = "One entry per ISO week (Monday 00:00 UTC "
            + "to the next, excluded), oldest first, ten categories each. from and to are ISO dates read as the Monday "
            + "of their week; the default is the last " + OwaspWeeklyHistoryService.DEFAULT_WEEKS + " weeks to the "
            + "current one, a to after the current week is read as the current week, and more than "
            + OwaspWeeklyHistoryService.MAX_WEEKS + " weeks, a from after to, or both project_id and solution_id answer "
            + "400. A project or a solution that does not exist and one the caller sees nothing of both answer 404. "
            + "Figures cover the targets the caller sees, within the scope. A week the weekly record captured carries "
            + "the recorded state, combined over the targets as the grid combines them: a category any target measured "
            + "counts every target's findings — a never-scanned target's included — and reads FINDINGS when they sum "
            + "above zero, else NO_FINDING; NOT_COVERED if every target reads it; else NOT_MEASURED, counting nothing. "
            + "open is unsettled, as the grid counts them at the week's last capture, and settled apart. A week before the record is reconstructed: state and "
            + "settled are null, never computed now for then, and open counts every issue placed in the category "
            + "that was first seen before the week's end, not resolved before it and not inside an earlier resolution a "
            + "reopening recorded, whatever its triage — the triage of a past date is not known. opened and resolved "
            + "are counted from the issues' dates on every week — resolved includes an earlier resolution a reopening "
            + "recorded — placed as the grid places them, without the grid's measurement switches. Known limit: a "
            + "reopening before this release recorded nothing, so such an issue keeps only its latest resolution and "
            + "counts as open in the weeks between an earlier resolution and that reopening.")
    @ApiResponse(responseCode = "200", description = "Weeks returned")
    @GetMapping("/weekly")
    public OwaspWeeklyHistoryService.OwaspWeeklyCoverage weeklyCoverage(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam(required = false) String from,
            @RequestParam(required = false) String to,
            @RequestParam(name = "project_id", required = false) Long projectId,
            @RequestParam(name = "solution_id", required = false) Long solutionId) {
        return weekly.weeks(new OwaspWeeklyHistoryService.Request(from, to, projectId, solutionId), allowanceOf(principal));
    }

    /** The caller's visibility with the projects it holds as such, which a project's or solution's scope reads. */
    private VisibilityService.Allowance allowanceOf(VectispirePrincipal principal) {
        return visibility.allowance(principal.user().orElse(null), principal.credentialRestriction());
    }

    /**
     * States what a category becomes when no scanner here can measure it.
     *
     * <p>The same rules as the statement of applicability, and they name no framework in
     * particular: a declaration must say whether the category applies, and where its evidence
     * lives when it is not here. An exclusion with no justification is refused for the same reason
     * as under ISO 27001 — a line that steps out of scope without saying why is the hole the
     * register exists to close.
     *
     * <p>The category is checked against the grid: {@code A11} does not exist, and a declaration
     * filed under a key nothing reads would be evidence nobody finds again.
     */
    @Operation(summary = "Declare a category", description = "What the organisation states about a category no scanner here can measure.")
    @ApiResponse(responseCode = "200", description = "Declaration written")
    @RequiresSecurityLead
    @PutMapping("/{category}/declaration")
    public Declaration declare(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @PathVariable String category,
            @RequestBody StatementOfApplicabilityController.DeclarationRequest body) {

        if (!OwaspCoverage.CATEGORIES.containsKey(category)) {
            throw new ResponseStatusException(
                    HttpStatus.NOT_FOUND,
                    category + " is not a category of the OWASP Top 10 2021.");
        }

        return declarations.declare(
                FRAMEWORK,
                category,
                new StatementOfApplicabilityService.Submission(
                        body.applicability(),
                        body.justification(),
                        body.implementation(),
                        body.evidenceSource(),
                        body.externalEvidence(),
                        body.owner(),
                        body.reviewDueAt()),
                principal.user().map(user -> user.username()).orElse("unknown"));
    }
}
