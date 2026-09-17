package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.Declaration;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.RequiresSecurityLead;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.OwaspCoverageService;
import com.asmolabs.vectispire.core.services.StatementOfApplicabilityService;
import com.asmolabs.vectispire.core.services.VisibilityService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
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
     * La clé sous laquelle les déclarations du Top 10 sont rangées.
     *
     * <p><b>Le Top 10 n'entre pas dans {@code ComplianceFramework}, et c'est délibéré.</b> Le moteur
     * de conformité n'évalue pas OWASP : l'ajouter à l'énumération le ferait apparaître dans les
     * évaluations, les résumés et la SoA, où il n'a rien à faire. La colonne {@code framework} de la
     * table des déclarations est une chaîne libre, et c'est tout ce dont cette clé a besoin.
     */
    static final String FRAMEWORK = "OWASP_2021";

    private final OwaspCoverageService coverage;
    private final VisibilityService visibility;
    private final StatementOfApplicabilityService declarations;

    public OwaspCoverageController(
            OwaspCoverageService coverage,
            VisibilityService visibility,
            StatementOfApplicabilityService declarations) {
        this.coverage = coverage;
        this.visibility = visibility;
        this.declarations = declarations;
    }

    /**
     * Une ligne de la grille, et ce que l'organisation en déclare.
     *
     * @param declaration {@code null} quand personne n'a rien déclaré. <b>C'est la case grise
     *     permanente que cette route existe pour supprimer</b> : deux catégories du Top 10 ne sont
     *     atteignables par aucune analyse statique — la conception non sûre ne se lit pas dans du
     *     code, et l'absence de journal ne laisse par définition aucune trace. Les laisser grises
     *     est honnête et ne porte aucune revue ; les déclarer dit qui l'affirme, avec quelle
     *     preuve, et quand cela se revoit.
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

    /** @param lines la grille dans l'ordre de la norme, chaque ligne avec sa déclaration s'il y en a une */
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
     * Déclare ce qu'une catégorie devient quand aucun scanner ne peut la mesurer.
     *
     * <p>Mêmes règles que la SoA, et elles ne parlent d'aucun référentiel en particulier : une
     * déclaration doit dire si la catégorie s'applique, et où vit sa preuve quand ce n'est pas ici.
     * Une exclusion sans justification est refusée pour la même raison que sous ISO 27001 — une
     * ligne qui se retire du périmètre sans dire pourquoi est le trou que le registre existe pour
     * fermer.
     *
     * <p>La catégorie est vérifiée contre la grille : {@code A11} n'existe pas, et une déclaration
     * rangée sous une clé que rien ne lit serait une preuve que personne ne retrouve.
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
                principal.user().map(user -> user.getUsername()).orElse("unknown"));
    }
}
