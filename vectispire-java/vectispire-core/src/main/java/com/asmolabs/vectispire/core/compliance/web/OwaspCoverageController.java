package com.asmolabs.vectispire.core.compliance.web;

import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.Declaration;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.access.web.security.RequiresAccount;
import com.asmolabs.vectispire.core.access.web.security.RequiresSecurityLead;
import com.asmolabs.vectispire.core.access.web.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.compliance.OwaspGridService;
import com.asmolabs.vectispire.core.compliance.OwaspWeeklyHistoryService;
import com.asmolabs.vectispire.core.compliance.StatementOfApplicabilityService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
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
 * <p>This route answers the same ten questions by rule ({@code OwaspCoverage}): a finding's type
 * places it — infrastructure checks in A05, dependency vulnerabilities and components past support in
 * A06, secrets in A07 — and a code-analysis finding goes where the rule that raised it declares
 * ({@code metadata.owasp}), never by a guess from its identifier. Every line carries why it says what
 * it says, and where no rule applies the answer is <em>not covered</em> rather than a guess.
 *
 * <h2>How many of ten is the deployment's, and the rest is the finding</h2>
 *
 * <p>The types reach three categories; code analysis adds whichever the installed rules declare, and
 * measures them once more than the rule this product ships is installed and a rule reaches the
 * repository's languages — so the count is a property of the installation, not a number to write
 * here. The categories nothing here reaches read <em>not covered</em>. A grid showing them green would be
 * claiming a clean bill of health over an examination that never happened — which is the same defect
 * the freshness window removed from the compliance matrix and the banner removed from the quality
 * screen, in the one place an auditor looks first.
 */
@Tag(name = "OWASP coverage", description = "The OWASP Top 10:2021 by rule, with what this deployment cannot see")
@RestController
@RequestMapping("/api/v1/owasp/coverage")
@RequiresAccount
public class OwaspCoverageController {

    private final OwaspGridService grids;
    private final OwaspWeeklyHistoryService weekly;
    private final VisibilityService visibility;
    private final StatementOfApplicabilityService declarations;

    public OwaspCoverageController(
            OwaspGridService grids,
            OwaspWeeklyHistoryService weekly,
            VisibilityService visibility,
            StatementOfApplicabilityService declarations) {
        this.grids = grids;
        this.weekly = weekly;
        this.visibility = visibility;
        this.declarations = declarations;
    }

    /**
     * The grid, over the reader's estate or one project or solution of it. The scope's rules, the
     * refusals included, are the weekly route's — one resolver serves both.
     */
    @Operation(summary = "OWASP Top 10:2021 coverage", description = "Each category's state — findings, nothing found, "
            + "unmeasured, or covered by no scanner here — with why: because, an English sentence, and reason, the same as "
            + "a code (one of reason.code's values) and the values the sentence is made of: the finding types it names "
            + "(types), and for a scope examined in part how many targets were not examined (missing), of how many "
            + "(applicable), and why (gaps). project_id or solution_id narrows every figure — findings, "
            + "whether anything was scanned, the code findings by category — to the scope's targets the caller sees; "
            + "both answer 400. A project or a solution that does not exist and one the caller sees nothing of both "
            + "answer 404; one seen in part is computed over its visible targets and says partial. The declarations "
            + "are per category and do not depend on the scope. unplacedCode counts the scope's open code findings no category "
            + "holds: their rule declares no 2021 category, and no CWE the OWASP 2021 lists map to one.")
    @ApiResponse(responseCode = "200", description = "Grid returned")
    @GetMapping
    public OwaspGridService.DeclaredGrid grid(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam(name = "project_id", required = false) Long projectId,
            @RequestParam(name = "solution_id", required = false) Long solutionId) {
        return grids.grid(projectId, solutionId, allowanceOf(principal));
    }

    /**
     * The grid as a file, for a register kept outside this product. The scope, its refusals and the reader
     * are the grid's: an export is the same read written down, and a second door with a looser lock is the
     * leak the evidence bundle once was.
     *
     * <p><b>The file is named by the scope's kind and number, never its name</b>: a project's name is chosen
     * by whoever may create one, and a header is not the place to find out what it can hold.
     */
    @Operation(operationId = "exportOwaspCoverageCsv", summary = "OWASP Top 10:2021 coverage as CSV",
            description = "The grid of GET /api/v1/owasp/coverage as a CSV attachment, one row per category in the "
                    + "standard's order, CRLF-terminated, every cell quoted and neutralized against spreadsheet formulas. "
                    + "Columns: category, title, state, findings, reason_code, reason (in language: en, the default, or "
                    + "fr; any other answers 400), the category's declaration (applicability, justification, "
                    + "implementation, evidence source, external evidence, owner, decided by and at, review due), and the "
                    + "scope (kind: project, solution or estate; id, name, partial) on every row. project_id and "
                    + "solution_id narrow it as they narrow the grid, with the same refusals: both answer 400, and a "
                    + "project or a solution that does not exist and one the caller sees nothing of both answer 404.")
    @ApiResponse(responseCode = "200", description = "CSV returned")
    @GetMapping(value = "/export.csv", produces = "text/csv")
    public ResponseEntity<String> exportCsv(
            @AuthenticationPrincipal VectispirePrincipal principal,
            @RequestParam(name = "project_id", required = false) Long projectId,
            @RequestParam(name = "solution_id", required = false) Long solutionId,
            @RequestParam(required = false) String language) {
        String document = grids.csv(projectId, solutionId, allowanceOf(principal), language);
        String filename = projectId != null ? "vectispire-owasp-coverage-project-" + projectId + ".csv"
                : solutionId != null ? "vectispire-owasp-coverage-solution-" + solutionId + ".csv"
                : "vectispire-owasp-coverage.csv";
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment().filename(filename).build().toString())
                .contentType(MediaType.parseMediaType("text/csv; charset=utf-8"))
                .body(document);
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
    @Operation(summary = "OWASP Top 10:2021 coverage, week by week", description = "One entry per ISO week (Monday 00:00 UTC "
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
            + "counts as open in the weeks between an earlier resolution and that reopening. reopened counts the issues "
            + "placed in the category that a reopening recorded in the triage history brought back during the week; it "
            + "is null on a week that began before reopenings were recorded (the migration's application, a day's "
            + "margin aside), where zero would claim what nobody saw, and reopenedRecordedFrom names the first week "
            + "that has it.")
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
                    category + " is not a category of the OWASP Top 10:2021.");
        }

        return declarations.declare(
                OwaspGridService.FRAMEWORK,
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
