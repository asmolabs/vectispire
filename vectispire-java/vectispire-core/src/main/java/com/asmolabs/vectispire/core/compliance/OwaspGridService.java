package com.asmolabs.vectispire.core.compliance;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.aireview.AdviceLanguage;
import com.asmolabs.vectispire.common.domain.compliance.StatementOfApplicability.Declaration;
import com.asmolabs.vectispire.common.domain.owasp.OwaspCoverage;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.compliance.internal.OwaspGridCsv;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The OWASP grid as the organisation reads it: what the rules measured, each category beside what was
 * declared about it.
 *
 * <p><b>One join, for the three readers of it.</b> The screen's grid, its CSV export and the evidence
 * bundle's section 15 each set the measurement against the declarations; the join lived in the grid's
 * controller, and a second and a third copy of it are where one comes to drop the declarations, or to
 * read them under another key. The scope and its refusals are {@link OwaspCoverageService}'s ({@link
 * OwaspScopes}), the reasons' words the PDF report's: nothing of either is restated here.
 */
@Service
public class OwaspGridService {

    /**
     * The key the Top 10 declarations are filed under.
     *
     * <p><b>The Top 10 does not join {@code ComplianceFramework}, and that is deliberate.</b> The
     * compliance engine does not evaluate OWASP: adding it to the enum would make it appear in
     * evaluations, summaries and the statement of applicability, where it has no business. The
     * declaration table's {@code framework} column is a free string, which is all this key needs.
     */
    public static final String FRAMEWORK = "OWASP_2021";

    private final OwaspCoverageService coverage;
    private final StatementOfApplicabilityService declarations;

    public OwaspGridService(OwaspCoverageService coverage, StatementOfApplicabilityService declarations) {
        this.coverage = coverage;
        this.declarations = declarations;
    }

    /**
     * One row of the grid, and what the organisation states about it.
     *
     * @param declaration {@code null} when nobody has stated anything. <b>That permanent grey
     *     square is what declaring exists to remove</b>: two Top 10 categories are beyond any
     *     static analysis — insecure design cannot be read out of code, and a missing log leaves,
     *     by definition, no trace. Leaving them grey is honest and carries no review; declaring
     *     them says who asserts it, on what evidence, and when it is looked at again.
     * @param because the reason in English, kept for every reader that does not translate — an export, a
     *     script, a client older than {@code reason}
     * @param reason the same reason as a code and the values its sentence is made of, which a screen
     *     renders in its reader's language (decision 0019). Added beside {@code because}, never in its place
     */
    public record DeclaredCoverageLine(
            String id,
            String title,
            OwaspCoverage.State state,
            long findings,
            String because,
            OwaspCoverage.CoverageReason reason,
            Declaration declaration) {

        static DeclaredCoverageLine of(OwaspCoverage.CoverageLine line, Declaration declaration) {
            return new DeclaredCoverageLine(
                    line.id(), line.title(), line.state(), line.findings(), line.because(), line.reason(), declaration);
        }
    }

    /**
     * @param lines the grid in the standard's order, each row with its declaration if it has one
     * @param scope the project or solution the grid was computed over, as the weekly route states it;
     *     null for the reader's estate. The declarations are the category's, whatever the scope
     * @param unplacedCode open code findings of the scope that no category holds — their rule declares no
     *     2021 category and no CWE the standard's lists hold. Counted beside the grid, never in a line
     */
    public record DeclaredGrid(
            List<DeclaredCoverageLine> lines,
            int covered,
            int withFindings,
            int unmeasured,
            OwaspWeeklyHistoryService.OwaspWeeklyScope scope,
            long unplacedCode) {}

    /**
     * The grid over one project or solution, or over the reader's estate when neither is named.
     *
     * @throws com.asmolabs.vectispire.common.domain.errors.InvalidInputException for both a project
     *     and a solution
     * @throws com.asmolabs.vectispire.common.domain.errors.NotFoundException for a project or a
     *     solution that does not exist and one the reader sees nothing of, in the same words
     */
    @Transactional(readOnly = true)
    public DeclaredGrid grid(Long projectId, Long solutionId, VisibilityService.Allowance allowance) {
        return declared(coverage.grid(projectId, solutionId, allowance));
    }

    /**
     * The grid over everything a visibility permits, with no scope stated — the evidence bundle's, which
     * is handed the caller's allowance and narrows with it like the sections around it.
     */
    @Transactional(readOnly = true)
    public DeclaredGrid grid(Visibility allowed) {
        return declared(coverage.estate(allowed));
    }

    /**
     * The grid as a CSV, one row per category, over the same scope and with the same refusals as {@link
     * #grid(Long, Long, VisibilityService.Allowance)}.
     *
     * @param language {@code en} or {@code fr}, the language of the reason column; English when absent
     * @throws com.asmolabs.vectispire.common.domain.errors.InvalidInputException for another language,
     *     and for both a project and a solution
     */
    @Transactional(readOnly = true)
    public String csv(Long projectId, Long solutionId, VisibilityService.Allowance allowance, String language) {
        // The language is read before the scope: a request that cannot be answered in any case is refused
        // before anything is looked up on its behalf.
        AdviceLanguage words = AdviceLanguage.parse(language);
        OwaspCoverageService.ScopedGrid scoped = coverage.grid(projectId, solutionId, allowance);
        return OwaspGridCsv.render(scoped.grid().lines(), byCategory(), scoped.scope(), words);
    }

    private DeclaredGrid declared(OwaspCoverageService.ScopedGrid scoped) {
        OwaspCoverage.Grid grid = scoped.grid();
        Map<String, Declaration> byCategory = byCategory();
        return new DeclaredGrid(
                grid.lines().stream()
                        .map(line -> DeclaredCoverageLine.of(line, byCategory.get(line.id())))
                        .toList(),
                grid.covered(),
                grid.withFindings(),
                grid.unmeasured(),
                scoped.scope(),
                scoped.unplacedCode());
    }

    private Map<String, Declaration> byCategory() {
        return declarations.declarations(FRAMEWORK).stream()
                .collect(Collectors.toMap(Declaration::controlId, Function.identity()));
    }
}
