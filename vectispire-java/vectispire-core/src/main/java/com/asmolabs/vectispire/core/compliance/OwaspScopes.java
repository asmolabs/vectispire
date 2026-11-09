package com.asmolabs.vectispire.core.compliance;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.access.VisibleScope;
import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import com.asmolabs.vectispire.core.access.VisibilityService;
import com.asmolabs.vectispire.core.targets.SolutionQueryService;
import org.springframework.stereotype.Component;

/**
 * The project or solution an OWASP figure is narrowed to — the one reading of it, for the live grid and
 * the weekly history alike.
 *
 * <p><b>One copy, because two would drift.</b> The weekly route resolved its scope inline; the grid
 * beside it on the same screen gained the same parameters, and a second copy of the refusal is the one
 * that comes to answer a hidden project differently from an absent one, or to read a partial project as
 * whole. The rule itself is {@code SolutionQueryService}'s ({@code RowVisibility}'s): a project or a
 * solution that does not exist and one the reader sees nothing of are refused in the same words (404),
 * and one seen in part is served over its visible targets, marked {@code partial}.
 */
@Component
class OwaspScopes {

    private final SolutionQueryService solutions;

    OwaspScopes(SolutionQueryService solutions) {
        this.solutions = solutions;
    }

    /**
     * What a figure is computed over.
     *
     * @param visibility the reader's visibility intersected with the scope's targets — every count is
     *     narrowed by it; the reader's own when no scope was named
     * @param scope the project or solution as far as the reader sees it, or null for the reader's estate
     */
    record Scoped(Visibility visibility, VisibleScope scope) {

        /** The scope as a response states it, or null for the reader's estate. */
        OwaspWeeklyHistoryService.OwaspWeeklyScope stated() {
            return scope == null ? null : new OwaspWeeklyHistoryService.OwaspWeeklyScope(
                    scope.kind().wireName(), scope.id(), scope.name(), scope.partial(), scope.targets().size());
        }
    }

    /**
     * The refusal of two scopes alone, for a caller that refuses the rest of its request before it reads
     * anything — the weekly route answers an unreadable window before a hidden project.
     */
    static void atMostOne(Long projectId, Long solutionId) {
        if (projectId != null && solutionId != null) {
            throw new InvalidInputException("Name a project or a solution, not both.");
        }
    }

    /**
     * @throws InvalidInputException for both a project and a solution
     * @throws com.asmolabs.vectispire.common.domain.errors.NotFoundException for a project or a solution
     *     that does not exist and one the reader sees nothing of, in the same words
     */
    Scoped resolve(Long projectId, Long solutionId, VisibilityService.Allowance allowance) {
        atMostOne(projectId, solutionId);
        VisibleScope scope = projectId != null
                ? solutions.visibleProject(projectId, allowance)
                : solutionId != null ? solutions.visibleSolution(solutionId, allowance) : null;
        // The scope's targets are already the reader's visible ones (`RowVisibility.visibleOf`), the
        // credential's restriction included: its visibility is the intersection, never the scope whole.
        return new Scoped(scope != null ? scope.visibility() : allowance.visibility(), scope);
    }
}
