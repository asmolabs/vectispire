package com.asmolabs.vectispire.common.domain.compliance;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * How a framework's verdict moved, and why it plausibly moved.
 *
 * <h2>A line alone would mislead</h2>
 *
 * <p><b>The score falls for reasons that are progress.</b> Registering a repository lowers it —
 * the new target has a backlog and no history. Switching code analysis on lowers it — findings
 * appear that were always there. A curve drawn without that context reports "we got worse" over
 * the month somebody started watching more, and a team reading that curve learns to watch less.
 *
 * <p><b>And it falls for reasons that are neither.</b> A freshness window expiring flips a verdict
 * from compliant to partial with nothing having changed in the estate at all: the evidence simply
 * aged. That is worth showing, and it is not the same event as a regression.
 *
 * <p>So each step carries an attribution. It is a plausible cause and not a proof — the estate can
 * grow and deteriorate in the same month — which is why {@link Movement#ESTATE_GREW} is worded as
 * what changed rather than as what it caused. Naming the shift is what stops the reader from
 * assuming the only explanation a bare line offers.
 */
public final class ComplianceHistory {

    private ComplianceHistory() {}

    /**
     * Below this, a score change is noise: a single issue opening or closing moves a percentage
     * by about this much on an ordinary estate, and a chart that annotates every one of them
     * annotates nothing.
     */
    private static final int NOISE = 2;

    /** Why the verdict is where it is, relative to the month before. */
    public enum Movement {
        /** First capture: there is nothing to compare it against, and saying so beats a zero. */
        FIRST,
        /** More targets are watched than last month. A fall here is the cost of looking wider. */
        ESTATE_GREW,
        /** Fewer targets. A rise here was bought by removing something, not by fixing it. */
        ESTATE_SHRANK,
        /** A setting moved — the freshness window, or a detector switched on or off. */
        RULES_CHANGED,
        /** Same shape, score up. The only movement that is unambiguously the work. */
        IMPROVED,
        /** Same shape, score down. */
        DECLINED,
        /** Same shape, no material change. */
        STEADY
    }

    /**
     * @param delta the score change since the month before; zero on the first capture
     * @param movement why it is where it is
     * @param because one sentence, meant to sit under the point on a chart and be quoted
     */
    public record Step(ComplianceSnapshot snapshot, int delta, Movement movement, String because) {}

    /**
     * @param comparable every step shares the shape of the last one. <b>Read this before the
     *     trend</b>: a series whose estate kept changing has a shape, not a trend
     */
    public record Series(ComplianceFramework framework, List<Step> steps, boolean comparable) {}

    /** One framework's months, oldest first, each attributed. */
    public static Series of(ComplianceFramework framework, List<ComplianceSnapshot> snapshots) {
        List<ComplianceSnapshot> ordered = snapshots.stream()
                .filter(snapshot -> snapshot.framework() == framework)
                .sorted(Comparator.comparing(ComplianceSnapshot::period))
                .toList();

        List<Step> steps = new ArrayList<>();
        ComplianceSnapshot previous = null;
        for (ComplianceSnapshot snapshot : ordered) {
            steps.add(step(snapshot, previous));
            previous = snapshot;
        }

        boolean comparable = steps.size() > 1
                && steps.stream().skip(1).allMatch(step ->
                        step.movement() != Movement.ESTATE_GREW
                                && step.movement() != Movement.ESTATE_SHRANK
                                && step.movement() != Movement.RULES_CHANGED);

        return new Series(framework, List.copyOf(steps), comparable);
    }

    /**
     * The order of the tests is the model.
     *
     * <p>A change of shape is named first, even when the score also moved, because the shape is
     * what makes the two months incomparable — attributing a fall to the work when the estate
     * grew by a third would be the chart telling a story the data does not carry.
     */
    private static Step step(ComplianceSnapshot snapshot, ComplianceSnapshot previous) {
        if (previous == null) {
            return new Step(snapshot, 0, Movement.FIRST,
                    "First capture for this framework: nothing to compare it against yet.");
        }

        int delta = snapshot.score() - previous.score();

        if (snapshot.targets() > previous.targets()) {
            return new Step(snapshot, delta, Movement.ESTATE_GREW,
                    "%d target(s) more than last month. A score that falls here is the cost of watching wider, not a regression."
                            .formatted(snapshot.targets() - previous.targets()));
        }
        if (snapshot.targets() < previous.targets()) {
            return new Step(snapshot, delta, Movement.ESTATE_SHRANK,
                    "%d target(s) fewer than last month. A score that rises here was bought by removing something."
                            .formatted(previous.targets() - snapshot.targets()));
        }
        if (!snapshot.shape().equals(previous.shape())) {
            return new Step(snapshot, delta, Movement.RULES_CHANGED, whatChanged(snapshot, previous));
        }
        if (delta >= NOISE) {
            return new Step(snapshot, delta, Movement.IMPROVED,
                    "Same estate, same rules, %d points up. This one is the work.".formatted(delta));
        }
        if (delta <= -NOISE) {
            return new Step(snapshot, delta, Movement.DECLINED,
                    "Same estate, same rules, %d points down.".formatted(-delta));
        }
        return new Step(snapshot, delta, Movement.STEADY, "Unchanged, within the noise of a single issue.");
    }

    private static String whatChanged(ComplianceSnapshot now, ComplianceSnapshot before) {
        if (now.freshnessDays() != before.freshnessDays()) {
            return "The freshness window moved from %d to %d days: the same estate is judged against a different rule."
                    .formatted(before.freshnessDays(), now.freshnessDays());
        }
        if (now.endOfLifeEnabled() != before.endOfLifeEnabled()) {
            return now.endOfLifeEnabled()
                    ? "End-of-life detection was switched on: findings appear that were always there."
                    : "End-of-life detection was switched off. Its findings stay open; they are simply no longer refreshed.";
        }
        return now.codeAnalysisReaches()
                ? "Code analysis now reaches this estate: findings appear that were always there."
                : "Code analysis no longer reaches this estate — switched off, or no rule covers the languages present.";
    }
}
