package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.VisibilityService;
import java.util.Optional;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import com.asmolabs.vectispire.core.repositories.Issues;
import com.asmolabs.vectispire.core.services.TargetNaming;
import java.util.List;
import org.springframework.data.domain.Limit;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * The aggregation that makes the quality screen worth having.
 *
 * <p><b>If this page were only {@code /issues?type=quality} it would not deserve to exist</b> —
 * it would be a filter. So it aggregates on axes the backlog does not offer: the most frequent
 * rules, the most affected files, the densest repositories. In front of a four-figure quality
 * backlog, "eight rules make seventy percent of the debt" is the only actionable framing.
 */
@RestController
@RequestMapping("/api/v1/quality")
@RequiresAccount
public class QualityController {

    /** Eight: enough to see a pattern, few enough that the list is read rather than scrolled. */
    private static final int TOP = 8;

    private final Issues issues;
    private final TargetNaming naming;
    private final VisibilityService visibility;

    public QualityController(Issues issues, TargetNaming naming, VisibilityService visibility) {
        this.issues = issues;
        this.naming = naming;
        this.visibility = visibility;
    }

    public record Bucket(String label, long count) {}

    /**
     * @param ruleCount how many distinct rules the whole backlog touches, not how many rows the
     *     list below holds — see {@code Issues.countDistinctRules}
     */
    public record Overview(
            long openCount,
            long ruleCount,
            long fileCount,
            List<Bucket> topRules,
            List<Bucket> topFiles,
            List<Bucket> topTargets) {}

    /**
     * The quality backlog's shape, <b>within the caller's allowance</b>.
     *
     * <p>A "top offenders" list is a ranking of other people's code: which rules their repository
     * trips most, which files are worst, which team is behind. It answered every account with the
     * estate's, so the one screen that names nothing sensitive individually named quite a lot of
     * it in aggregate.
     *
     * <p>The counts are grouped and limited in SQL either way — this was never an unbounded read.
     * What it lacked was an allowance.
     */
    @GetMapping("/overview")
    public Overview overview(@AuthenticationPrincipal VectispirePrincipal principal) {
        String state = IssueState.OPEN.wireName();
        String type = FindingType.QUALITY.wireName();

        Optional<List<Long>> repoIds = visibility
                .of(principal.user().orElse(null), principal.credentialRestriction())
                .asFilter()
                .map(targets -> targets.stream()
                        .filter(ScanTarget.Repository.class::isInstance)
                        .map(target -> ((ScanTarget.Repository) target).id())
                        .toList());

        // An allowance holding no repository is answered without a query: `in ()` is not portable
        // and the answer is known. Falling back to the unrestricted form here would be the
        // inversion `Visibility` exists to prevent.
        if (repoIds.isPresent() && repoIds.get().isEmpty()) {
            return new Overview(0, 0, 0, List.of(), List.of(), List.of());
        }

        if (repoIds.isPresent()) {
            List<Long> ids = repoIds.get();
            return new Overview(
                    issues.countByStateAndTypeWithin(state, type, ids),
                    issues.countDistinctRulesWithin(state, type, ids),
                    issues.countDistinctFilesWithin(state, type, ids),
                    buckets(issues.countOpenByRuleWithin(state, type, ids, Limit.of(TOP))),
                    buckets(issues.countOpenByFileWithin(state, type, ids, Limit.of(TOP))),
                    namedTargets(issues.countOpenByTargetRepositoryWithin(state, type, ids, Limit.of(TOP))));
        }

        List<Bucket> byRule = buckets(issues.countOpenByRule(state, type, Limit.of(TOP)));
        List<Bucket> byFile = buckets(issues.countOpenByFile(state, type, Limit.of(TOP)));

        List<Bucket> byTarget = namedTargets(issues.countOpenByTargetRepository(state, type, Limit.of(TOP)));

        return new Overview(
                issues.countByStateAndType(state, type),
                issues.countDistinctRules(state, type),
                issues.countDistinctFiles(state, type),
                byRule,
                byFile,
                byTarget);
    }

    /**
     * The grouping returns a repository id; showing it as it stands would make the reader
     * translate a foreign key in their head. Resolved here rather than by a join: the list is
     * eight rows, and joining inside the grouped query would force grouping on the name too.
     */
    private List<Bucket> namedTargets(List<Object[]> rows) {
        TargetNaming.Names names = naming.all();
        return rows.stream()
                .map(row -> new Bucket(
                        names.repositories().getOrDefault(((Number) row[0]).longValue(), TargetNaming.DELETED),
                        ((Number) row[1]).longValue()))
                .toList();
    }

    private static List<Bucket> buckets(List<Object[]> rows) {
        return rows.stream()
                .map(row -> new Bucket((String) row[0], ((Number) row[1]).longValue()))
                .toList();
    }
}
