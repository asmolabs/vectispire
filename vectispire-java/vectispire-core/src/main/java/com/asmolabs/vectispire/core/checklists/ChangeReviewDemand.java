package com.asmolabs.vectispire.core.checklists;

import com.asmolabs.vectispire.common.domain.checklists.ChecklistRule;
import com.asmolabs.vectispire.core.checklists.persistence.BoundRuleUse;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistItemRepository;
import com.asmolabs.vectispire.core.targets.SolutionQueryService;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Which repositories a {@code change_review} line asks about, for which branch and how far back (decision 0037, lot
 * G3) — what the forges' hourly reading reads before calling a forge, so that a forge is asked only about the
 * repositories of a project whose checklist measures it, and only as far back as the widest window bound to it.
 *
 * <p>The checklists that are not superseded count — a draft, a submission, a signed-off revision a reader opens:
 * each measures its lines again when read. A project's repositories are the ones filed in it now, as the
 * whole-project guard reads them.
 */
@Service
public class ChangeReviewDemand {

    /** The canonical form's writing of the kind: keys sorted, no whitespace (see {@link ChecklistRule#canonical}). */
    static final String KIND_TOKEN = "%\"kind\":\"" + ChecklistRule.Kind.CHANGE_REVIEW.wireName() + "\"%";

    /**
     * One repository and branch to read.
     *
     * @param branch empty for the default branch the forge names
     * @param windowDays the widest window any line bound to it asks
     */
    public record Wanted(long repositoryId, Optional<String> branch, int windowDays) {}

    private final ChecklistItemRepository items;
    private final SolutionQueryService projects;

    public ChangeReviewDemand(ChecklistItemRepository items, SolutionQueryService projects) {
        this.items = items;
        this.projects = projects;
    }

    /** Every repository and branch asked about, each with its widest window, by repository then branch. */
    @Transactional(readOnly = true)
    public List<Wanted> wanted() {
        Map<Long, Map<Optional<String>, Integer>> byProject = new HashMap<>();
        for (BoundRuleUse use : items.boundInUse(ChecklistStatus.SUPERSEDED.wireName(), KIND_TOKEN)) {
            if (ChecklistRule.fromCanonical(use.boundRule()) instanceof ChecklistRule.ChangeReview review) {
                byProject.computeIfAbsent(use.projectId(), id -> new HashMap<>())
                        .merge(review.branch(), review.windowDays(), Math::max);
            }
        }
        Map<Long, Map<Optional<String>, Integer>> byRepository = new LinkedHashMap<>();
        byProject.forEach((projectId, branches) -> projects.members(projectId).ifPresent(members ->
                members.repositoryIds().forEach(repository -> branches.forEach((branch, window) ->
                        byRepository.computeIfAbsent(repository, id -> new HashMap<>()).merge(branch, window, Math::max)))));
        List<Wanted> wanted = new ArrayList<>();
        byRepository.forEach((repository, branches) -> branches.forEach((branch, window) ->
                wanted.add(new Wanted(repository, branch, window))));
        wanted.sort(java.util.Comparator.comparingLong(Wanted::repositoryId)
                .thenComparing(want -> want.branch().orElse("")));
        return wanted;
    }
}
