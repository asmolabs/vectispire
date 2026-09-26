package com.asmolabs.vectispire.core.api;

import com.asmolabs.vectispire.core.api.security.RequiresAccount;
import com.asmolabs.vectispire.core.api.security.VectispirePrincipal;
import com.asmolabs.vectispire.core.services.QualityQueryService;
import com.asmolabs.vectispire.core.services.access.VisibilityService;
import java.util.List;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
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

    private final QualityQueryService quality;
    private final VisibilityService visibility;

    public QualityController(QualityQueryService quality, VisibilityService visibility) {
        this.quality = quality;
        this.visibility = visibility;
    }

    public record Bucket(String label, long count) {}

    /**
     * @param ruleCount how many distinct rules the whole backlog touches, not how many rows the
     *     list below holds — see {@code Issues.countDistinctRules}
     */
    public record QualityOverview(
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
    public QualityOverview overview(@AuthenticationPrincipal VectispirePrincipal principal) {
        QualityQueryService.Overview overview = quality.overview(
                visibility.of(principal.user().orElse(null), principal.credentialRestriction()));
        return new QualityOverview(
                overview.openCount(),
                overview.ruleCount(),
                overview.fileCount(),
                buckets(overview.topRules()),
                buckets(overview.topFiles()),
                buckets(overview.topTargets()));
    }

    private static List<Bucket> buckets(List<QualityQueryService.Bucket> buckets) {
        return buckets.stream().map(bucket -> new Bucket(bucket.label(), bucket.count())).toList();
    }
}
