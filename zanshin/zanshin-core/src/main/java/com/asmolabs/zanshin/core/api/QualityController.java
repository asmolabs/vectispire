package com.asmolabs.zanshin.core.api;

import com.asmolabs.zanshin.common.domain.issues.FindingType;
import com.asmolabs.zanshin.common.domain.issues.IssueState;
import com.asmolabs.zanshin.core.repositories.Issues;
import com.asmolabs.zanshin.core.services.TargetNaming;
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
public class QualityController {

    /** Eight: enough to see a pattern, few enough that the list is read rather than scrolled. */
    private static final int TOP = 8;

    private final Issues issues;
    private final TargetNaming naming;

    public QualityController(Issues issues, TargetNaming naming) {
        this.issues = issues;
        this.naming = naming;
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

    @GetMapping("/overview")
    public Overview overview() {
        String state = IssueState.OPEN.wireName();
        String type = FindingType.QUALITY.wireName();

        List<Bucket> byRule = buckets(issues.countOpenByRule(state, type, Limit.of(TOP)));
        List<Bucket> byFile = buckets(issues.countOpenByFile(state, type, Limit.of(TOP)));

        TargetNaming.Names names = naming.all();
        // The grouping returns a repository id; showing it as it stands would make the reader
        // translate a foreign key in their head. Resolved here rather than by a join: the list is
        // eight rows, and joining inside the grouped query would force grouping on the name too.
        List<Bucket> byTarget = issues.countOpenByTargetRepository(state, type, Limit.of(TOP)).stream()
                .map(row -> new Bucket(
                        names.repositories().getOrDefault(((Number) row[0]).longValue(), TargetNaming.DELETED),
                        ((Number) row[1]).longValue()))
                .toList();

        return new Overview(
                issues.countByStateAndType(state, type),
                issues.countDistinctRules(state, type),
                issues.countDistinctFiles(state, type),
                byRule,
                byFile,
                byTarget);
    }

    private static List<Bucket> buckets(List<Object[]> rows) {
        return rows.stream()
                .map(row -> new Bucket((String) row[0], ((Number) row[1]).longValue()))
                .toList();
    }
}
