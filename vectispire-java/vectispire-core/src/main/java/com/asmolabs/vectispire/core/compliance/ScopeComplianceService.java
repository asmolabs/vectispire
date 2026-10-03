package com.asmolabs.vectispire.core.compliance;

import com.asmolabs.vectispire.common.domain.access.VisibleScope;
import com.asmolabs.vectispire.common.domain.scorecard.SecurityScorecard;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.compliance.ComplianceService.ComplianceSummary;
import com.asmolabs.vectispire.core.posture.SecurityScorecardService;
import com.asmolabs.vectispire.core.targets.SolutionQueryService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * A project's or a solution's compliance and score — the estate's, computed over the scope's targets
 * (decision 0023: "aggregates per project and per solution … are computed over the member repositories
 * the reader may see — a partial grant sees a partial project, and says so").
 *
 * <p><b>No computation of its own.</b> The estate summary already takes a {@code Visibility} and narrows
 * every input by it — the targets and their posture, the open counts, the overdue ones, the inventory,
 * the resolutions the MTTR averages — so the scope's is the estate's asked with the scope's visible
 * targets as the allowance: the same controls, the same coverage and freshness caps, the same {@code
 * NO_DATA} when none of those targets was scanned. The score is the scorecard's in the same way
 * ({@link SecurityScorecardService#getScopeScorecard}: the scope's weakest scanned target, decision
 * 0036). A second copy of either would be a second answer to "is this product compliant", and the two
 * would drift.
 *
 * <p><b>A partly visible scope is computed over its visible part and says {@code partial}</b> rather than
 * being refused. Every input is narrowed to the visible targets, so the figures carry nothing of the
 * hidden ones — the same property that lets a restricted reader see the estate summary over what they
 * see, and the tree and the backlog show a partial project's figures. The checklists refuse a partial
 * reader for a reason that does not hold here: a checklist's lines speak for every repository of the
 * project, in words, and are signed; this summary speaks for the targets it lists, which are the
 * caller's own, and is stored nowhere.
 *
 * <p>The platform's own controls (encryption, the audit mirror, four-eyes, the sign-in policy) are the
 * deployment's and read the same in every scope, as they do in a single target's summary.
 */
@Service
public class ScopeComplianceService {

    private final SolutionQueryService solutions;
    private final ComplianceService compliance;
    private final SecurityScorecardService scorecards;

    public ScopeComplianceService(
            SolutionQueryService solutions, ComplianceService compliance, SecurityScorecardService scorecards) {
        this.solutions = solutions;
        this.compliance = compliance;
        this.scorecards = scorecards;
    }

    /**
     * @param kind {@code project} or {@code solution}
     * @param partial the scope holds targets the caller does not see; both figures cover the visible ones
     * @param targetCount the visible targets both figures were computed over
     * @param compliance the estate summary's shape, narrowed to those targets — its {@code targets} is
     *     the scope's matrix
     * @param scorecard the portfolio scorecard's, narrowed likewise
     */
    public record ScopeCompliance(
            String kind,
            long id,
            String name,
            boolean partial,
            int targetCount,
            ComplianceSummary compliance,
            SecurityScorecard scorecard) {}

    /** "Project not found." for a project that does not exist and one the caller sees nothing of. */
    @Transactional(readOnly = true)
    public ScopeCompliance ofProject(long projectId, VisibilityService.Allowance allowance) {
        return of(solutions.visibleProject(projectId, allowance));
    }

    /** "Solution not found." for a solution that does not exist and one the caller sees nothing of. */
    @Transactional(readOnly = true)
    public ScopeCompliance ofSolution(long solutionId, VisibilityService.Allowance allowance) {
        return of(solutions.visibleSolution(solutionId, allowance));
    }

    private ScopeCompliance of(VisibleScope scope) {
        return new ScopeCompliance(
                scope.kind().wireName(),
                scope.id(),
                scope.name(),
                scope.partial(),
                scope.targets().size(),
                compliance.getSummary(scope.visibility()),
                scorecards.getScopeScorecard(scope));
    }
}
