package com.asmolabs.vectispire.common.domain.trends;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.vectispire.common.domain.trends.PostureTrendAnalytics.IssueObservation;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The window filter changes what is read and not what is reported.
 *
 * <p><b>The claim under test.</b> {@code touchesWindow} says an issue resolved before the window
 * opened cannot affect the trend — not its daily series, not its totals, not its averages. The
 * dashboard now relies on that to read a fraction of the estate instead of all of it. If the
 * claim is wrong the page shows different numbers than it used to, and nothing else in the suite
 * would notice: the characterisation tests feed the unfiltered path, and every other assertion
 * about the dashboard is about its shape.
 *
 * <p>So this compares the two paths directly, on the same observations: everything, versus only
 * what the predicate keeps. Every field of the result must match, the daily series point by
 * point.
 *
 * <p><b>Randomised, with a fixed seed.</b> A hand-written fixture proves the predicate for the
 * cases its author thought of, which are the cases they already believed. Two hundred issues
 * drawn across and around the window boundary — resolved inside it, resolved the instant before
 * it, never resolved, resolved before ever being seen — cover the combinations nobody enumerates
 * by hand. The seed is fixed so a failure is reproducible rather than a rumour.
 */
@DisplayName("filtering to the window")
class PostureWindowEquivalenceTest {

    private static final Instant NOW = Instant.parse("2026-03-01T00:00:00Z");
    private static final long DAY = 86_400L;

    @Test
    @DisplayName("reports exactly what reading the whole estate reported")
    void reports_exactly_what_the_unfiltered_path_reported() {
        for (int windowDays : new int[] {7, 10, 30, 90}) {
            List<IssueObservation> everything = anEstate(200, windowDays);
            Instant start = PostureTrendAnalytics.windowStart(windowDays, NOW);

            List<IssueObservation> touching = everything.stream()
                    .filter(obs -> PostureTrendAnalytics.touchesWindow(obs, start))
                    .toList();

            // **Both sides go through the four-argument engine, and only the input differs.**
            // Comparing against the three-argument facade would prove nothing: the facade filters
            // with the very predicate under test, so a broken predicate would break both sides
            // identically and the assertion would pass. That mistake was made here first, and it
            // survived deleting a clause from `touchesWindow`.
            List<PostureTrendAnalytics.TargetMaturityScore> scoreboard =
                    PostureTrendAnalytics.calculate(windowDays, NOW, everything).targetScoreboard();

            PostureTrendAnalytics unfiltered =
                    PostureTrendAnalytics.calculate(windowDays, NOW, everything, scoreboard);
            PostureTrendAnalytics windowed =
                    PostureTrendAnalytics.calculate(windowDays, NOW, touching, scoreboard);

            assertThat(touching)
                    .as("the filter has to actually drop something, or this proves nothing")
                    .hasSizeLessThan(everything.size());

            assertThat(windowed)
                    .as("window of %d days over %d issues, %d of them read", windowDays, everything.size(), touching.size())
                    .isEqualTo(unfiltered);
        }
    }

    @Test
    @DisplayName("keeps an issue whose resolution precedes its first sighting")
    void keeps_the_impossible_row() {
        // Nonsense that exists in real data: resolved before it was ever seen, and seen inside
        // the window. The engine counts it as opened in the window, so the filter must keep it —
        // this is the clause that looks redundant in `touchesWindow` and is not.
        Instant start = PostureTrendAnalytics.windowStart(10, NOW);
        IssueObservation backwards = new IssueObservation(
                1L, "REPOSITORY", "repo", "HIGH", start.plusSeconds(DAY), start.minusSeconds(DAY));

        assertThat(PostureTrendAnalytics.touchesWindow(backwards, start)).isTrue();

        List<IssueObservation> estate = List.of(backwards);
        assertThat(PostureTrendAnalytics.calculate(10, NOW, estate).totalOpenedInWindow())
                .as("dropping it would silently lower the count of issues opened in the window")
                .isEqualTo(1);
    }

    @Test
    @DisplayName("drops an issue resolved before the window and changes nothing by doing so")
    void drops_the_settled_past() {
        Instant start = PostureTrendAnalytics.windowStart(10, NOW);
        IssueObservation ancient = new IssueObservation(
                1L,
                "REPOSITORY",
                "repo",
                "CRITICAL",
                start.minusSeconds(30 * DAY),
                start.minusSeconds(20 * DAY));

        assertThat(PostureTrendAnalytics.touchesWindow(ancient, start)).isFalse();

        IssueObservation live = new IssueObservation(
                1L, "REPOSITORY", "repo", "HIGH", start.plusSeconds(DAY), null);

        PostureTrendAnalytics withAncient = PostureTrendAnalytics.calculate(10, NOW, List.of(ancient, live));
        PostureTrendAnalytics withoutIt = PostureTrendAnalytics.calculate(
                10, NOW, List.of(live), withAncient.targetScoreboard());

        assertThat(withoutIt).isEqualTo(withAncient);
    }

    /**
     * An estate whose issues cluster around the window boundary, where the predicate either holds
     * or does not.
     */
    private static List<IssueObservation> anEstate(int count, int windowDays) {
        Random random = new Random(20260301L + windowDays);
        Instant start = PostureTrendAnalytics.windowStart(windowDays, NOW);
        String[] severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", null};
        List<IssueObservation> issues = new ArrayList<>();

        for (int i = 0; i < count; i++) {
            long targetId = 1 + random.nextInt(6);
            String kind = random.nextBoolean() ? "REPOSITORY" : "CONTAINER";
            String severity = severities[random.nextInt(severities.length)];

            // Spread first sightings from well before the window to inside it, and let a few
            // have none at all.
            Instant firstSeen = random.nextInt(20) == 0
                    ? null
                    : start.plusSeconds((random.nextInt(2 * windowDays + 60) - windowDays - 40) * DAY);

            Instant resolvedAt;
            int fate = random.nextInt(4);
            if (fate == 0) {
                resolvedAt = null;
            } else if (fate == 1 && firstSeen != null) {
                // Closed before the window opened: the rows the filter is meant to drop.
                resolvedAt = start.minusSeconds((1 + random.nextInt(30)) * DAY);
            } else {
                resolvedAt = start.plusSeconds(random.nextInt(windowDays + 1) * DAY);
            }

            issues.add(new IssueObservation(
                    targetId, kind, kind.charAt(0) + "-" + targetId, severity, firstSeen, resolvedAt));
        }
        // **Guaranteed, not hoped for.** A first run of this fixture happened to generate no row
        // whose resolution precedes its first sighting *inside* the window, so removing that
        // clause from the predicate left the randomised comparison green — a test that passes
        // for the wrong reason is worse than one that is absent. These make the case certain.
        for (int i = 0; i < 5; i++) {
            issues.add(new IssueObservation(
                    1L,
                    "REPOSITORY",
                    "R-1",
                    "CRITICAL",
                    start.plusSeconds((1L + i) * DAY),
                    start.minusSeconds((1L + i) * DAY)));
        }

        return List.copyOf(issues);
    }
}
