package com.asmolabs.vectispire.core.posture;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import com.asmolabs.vectispire.common.domain.issues.FindingType;
import com.asmolabs.vectispire.common.domain.issues.IssueState;
import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.issues.IssueCatalog;
import com.asmolabs.vectispire.core.targets.TargetNaming;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Service;

/**
 * The shape of the open quality backlog: the most frequent rules, the most affected files, the
 * densest repositories — within the caller's allowance.
 *
 * <p>A "top offenders" list is a ranking of other people's code, so it is narrowed like every
 * other read. The counts are grouped and limited in SQL either way.
 */
@Service
public class QualityQueryService {

    /** Eight: enough to see a pattern, few enough that the list is read rather than scrolled. */
    private static final int TOP = 8;

    private final IssueCatalog issues;
    private final TargetNaming naming;

    public QualityQueryService(IssueCatalog issues, TargetNaming naming) {
        this.issues = issues;
        this.naming = naming;
    }

    public record Bucket(String label, long count) {}

    /**
     * @param ruleCount how many distinct rules the whole backlog touches, not how many rows
     *     {@code topRules} holds — see {@code Issues.countDistinctRules}
     */
    public record Overview(
            long openCount,
            long ruleCount,
            long fileCount,
            List<Bucket> topRules,
            List<Bucket> topFiles,
            List<Bucket> topTargets) {}

    public Overview overview(Visibility allowed) {
        String state = IssueState.OPEN.wireName();
        String type = FindingType.QUALITY.wireName();

        Optional<List<Long>> repoIds = allowed
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
                    buckets(issues.countOpenByRuleWithin(state, type, ids, TOP)),
                    buckets(issues.countOpenByFileWithin(state, type, ids, TOP)),
                    namedTargets(issues.countOpenByTargetRepositoryWithin(state, type, ids, TOP)));
        }

        List<Bucket> byRule = buckets(issues.countOpenByRule(state, type, TOP));
        List<Bucket> byFile = buckets(issues.countOpenByFile(state, type, TOP));

        List<Bucket> byTarget = namedTargets(issues.countOpenByTargetRepository(state, type, TOP));

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
    private List<Bucket> namedTargets(List<IssueCatalog.RepositoryCount> rows) {
        TargetNaming.Names names = naming.all();
        return rows.stream()
                .map(row -> new Bucket(
                        names.repositories().getOrDefault(row.repositoryId(), TargetNaming.DELETED),
                        row.count()))
                .toList();
    }

    private static List<Bucket> buckets(List<IssueCatalog.KeyCount> rows) {
        return rows.stream()
                .map(row -> new Bucket(row.key(), row.count()))
                .toList();
    }
}
