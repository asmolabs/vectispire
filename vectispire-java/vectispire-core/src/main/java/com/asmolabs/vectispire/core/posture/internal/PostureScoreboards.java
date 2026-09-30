package com.asmolabs.vectispire.core.posture.internal;

import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.common.domain.trends.PostureTrendAnalytics;
import com.asmolabs.vectispire.common.domain.trends.PostureTrendAnalytics.TargetMaturityScore;
import com.asmolabs.vectispire.core.issues.persistence.queries.IssueAggregates;
import com.asmolabs.vectispire.core.posture.SecurityScorecardService.TargetGrade;
import com.asmolabs.vectispire.core.targets.TargetNaming;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * The all-time half of the posture dashboard: the maturity ranking, one row per target.
 *
 * <p><b>It grades nothing.</b> Each row's score and grade are the target's scorecard's, handed over
 * by {@code SecurityScorecardService.gradeEach}; what is assembled here is the ranking — which
 * targets are listed, what they have closed and how fast, and the order. It used to grade too, a
 * hundred less the open backlog with weights of its own, and a target read one grade on the
 * dashboard and another on its card and its badge.
 *
 * <p><b>Why this half cannot be windowed.</b> The ranking reports what a target carries and what it
 * has closed since it was added. Filtering it to the trend's window would change published figures
 * — so the window narrows the curve and leaves this alone.
 */
public final class PostureScoreboards {

    private PostureScoreboards() {}

    /**
     * Graded first, best score first; after them the targets with no grade. Ties keep the order the
     * targets were listed in — repositories, then images, each by id — rather than a hash map's.
     */
    private static final Comparator<TargetMaturityScore> RANKING = Comparator.comparing(
            TargetMaturityScore::securityScore, Comparator.nullsLast(Comparator.<Integer>reverseOrder()));

    private static final Comparator<ScanTarget> LISTING = Comparator
            .comparing((ScanTarget target) -> target instanceof ScanTarget.Container)
            .thenComparing(PostureScoreboards::idOf);

    /**
     * @param grades every target the caller may see that holds an open issue or a completed scan,
     *     graded as its card grades it — a clean scanned target among them, at 100
     * @param resolved one row per target: how many it has closed and how long they took. A target
     *     listed here alone holds no completed scan — {@code grades} would carry it otherwise — and
     *     ranks as {@link TargetGrade#UNOBSERVED}, its closed issues shown
     * @param names resolved once by the caller, which already needs them for the curve
     */
    public static List<TargetMaturityScore> from(
            Map<ScanTarget, TargetGrade> grades,
            List<IssueAggregates.TargetResolutions> resolved,
            TargetNaming.Names names) {

        Map<ScanTarget, IssueAggregates.TargetResolutions> closed = new HashMap<>();
        for (IssueAggregates.TargetResolutions row : resolved) {
            ScanTarget target = targetOf(row.repoId(), row.containerId());
            if (target != null) {
                closed.put(target, row);
            }
        }

        List<TargetMaturityScore> ranking = new ArrayList<>();
        for (ScanTarget target : listed(grades, resolved)) {
            ranking.add(row(target, grades.getOrDefault(target, TargetGrade.UNOBSERVED), closed.get(target), names));
        }
        ranking.sort(RANKING);
        return ranking;
    }

    /** Every target the ranking lists, in the order ties keep — the caller names exactly these. */
    public static List<ScanTarget> listed(
            Map<ScanTarget, TargetGrade> grades, List<IssueAggregates.TargetResolutions> resolved) {
        Set<ScanTarget> listed = new LinkedHashSet<>(grades.keySet());
        resolved.forEach(row -> {
            ScanTarget target = targetOf(row.repoId(), row.containerId());
            if (target != null) {
                listed.add(target);
            }
        });
        return listed.stream().sorted(LISTING).toList();
    }

    private static TargetMaturityScore row(
            ScanTarget target,
            TargetGrade grade,
            IssueAggregates.TargetResolutions closed,
            TargetNaming.Names names) {

        Long repoId = target instanceof ScanTarget.Repository repository ? repository.id() : null;
        Long containerId = target instanceof ScanTarget.Container container ? container.id() : null;
        return new TargetMaturityScore(
                idOf(target),
                repoId != null ? "REPOSITORY" : "CONTAINER",
                names.of(repoId, containerId),
                grade.critical(),
                grade.high(),
                grade.medium(),
                grade.low(),
                closed == null ? 0 : closed.resolved(),
                // Seconds to days, and the engine's own rounding: the average arrives from the
                // database, and has to read as the window's MTTR does.
                closed == null || closed.averageSeconds() == null
                        ? null
                        : PostureTrendAnalytics.roundDays(closed.averageSeconds() / 86400.0),
                grade.score(),
                grade.grade());
    }

    private static long idOf(ScanTarget target) {
        return switch (target) {
            case ScanTarget.Repository repository -> repository.id();
            case ScanTarget.Container container -> container.id();
        };
    }

    /** A row attached to neither target ranks nowhere: there is no card to agree with. */
    private static ScanTarget targetOf(Long repoId, Long containerId) {
        if (repoId != null) {
            return new ScanTarget.Repository(repoId);
        }
        return containerId == null ? null : new ScanTarget.Container(containerId);
    }
}
