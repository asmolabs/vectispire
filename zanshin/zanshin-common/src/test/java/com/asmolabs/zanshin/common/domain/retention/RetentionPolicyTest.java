package com.asmolabs.zanshin.common.domain.retention;

import static org.assertj.core.api.Assertions.assertThat;

import com.asmolabs.zanshin.common.domain.targets.ScanTarget;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

@DisplayName("payload retention")
class RetentionPolicyTest {

    private static final Instant NOW = Instant.parse("2026-08-13T10:00:00Z");
    private static final ScanTarget REPO = new ScanTarget.Repository(1);
    private static final ScanTarget IMAGE = new ScanTarget.Container(1);

    /** Newest first, as the query must deliver them. */
    private static List<RetentionPolicy.Candidate> scans(ScanTarget target, long firstId, int count, int daysApart) {
        List<RetentionPolicy.Candidate> candidates = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            candidates.add(new RetentionPolicy.Candidate(
                    firstId + i, target, NOW.minus(Duration.ofDays((long) i * daysApart))));
        }
        return candidates;
    }

    @Test
    @DisplayName("the two rules combine: outside the window AND old enough")
    void bothRulesMustHold() {
        // Requiring both is what lets a target scanned twice a year keep its payloads while a
        // target scanned hourly stays bounded. Either rule alone fails one of the two.
        RetentionPolicy policy = new RetentionPolicy(3, Duration.ofDays(90));

        // Ten scans, one per day: all recent, so nothing is purged despite six being outside
        // the keep window.
        assertThat(policy.prunable(scans(REPO, 1, 10, 1), NOW)).isEmpty();

        // Ten scans, one per year: all old, but the three most recent are inside the window.
        assertThat(policy.prunable(scans(REPO, 1, 10, 365), NOW)).containsExactly(4L, 5L, 6L, 7L, 8L, 9L, 10L);
    }

    @Test
    @DisplayName("counts the keep window per target, not across all of them")
    void keepWindowIsPerTarget() {
        RetentionPolicy policy = new RetentionPolicy(2, Duration.ofDays(30));

        List<RetentionPolicy.Candidate> candidates = new ArrayList<>(scans(REPO, 1, 3, 365));
        candidates.addAll(scans(IMAGE, 10, 3, 365));

        // Two kept on each side, not two in total.
        assertThat(policy.prunable(candidates, NOW)).containsExactly(3L, 12L);
    }

    @Test
    @DisplayName("a repository and a container sharing an id keep their own windows")
    void targetsWithTheSameIdAreDistinct() {
        // Keyed by id alone, one target's scans would count against the other's window and
        // half the payloads would go early.
        RetentionPolicy policy = new RetentionPolicy(1, Duration.ofDays(1));

        List<RetentionPolicy.Candidate> candidates = new ArrayList<>();
        candidates.add(new RetentionPolicy.Candidate(1, REPO, NOW.minus(Duration.ofDays(400))));
        candidates.add(new RetentionPolicy.Candidate(2, IMAGE, NOW.minus(Duration.ofDays(400))));

        assertThat(policy.prunable(candidates, NOW)).isEmpty();
    }

    @Test
    @DisplayName("zero on both axes purges nothing at all")
    void disabledPolicyPurgesNothing() {
        RetentionPolicy disabled = new RetentionPolicy(RetentionPolicy.UNLIMITED, Duration.ZERO);

        assertThat(disabled.isEnabled()).isFalse();
        assertThat(disabled.prunable(scans(REPO, 1, 100, 365), NOW)).isEmpty();
    }

    @Test
    @DisplayName("zero on one axis lifts that limit only")
    void unlimitedOnOneAxis() {
        // No age limit: only the keep window decides, so everything past the tenth goes
        // whatever its age.
        RetentionPolicy noAgeLimit = new RetentionPolicy(2, Duration.ZERO);
        assertThat(noAgeLimit.prunable(scans(REPO, 1, 4, 1), NOW)).containsExactly(3L, 4L);

        // No keep window: only age decides.
        RetentionPolicy noKeepWindow = new RetentionPolicy(RetentionPolicy.UNLIMITED, Duration.ofDays(2));
        assertThat(noKeepWindow.prunable(scans(REPO, 1, 4, 1), NOW)).containsExactly(3L, 4L);
    }

    @Test
    @DisplayName("the cutoff is empty when age is unlimited")
    void cutoffFollowsTheAgeLimit() {
        assertThat(new RetentionPolicy(5, Duration.ZERO).cutoff(NOW)).isEmpty();
        assertThat(RetentionPolicy.DEFAULT.cutoff(NOW)).contains(NOW.minus(Duration.ofDays(90)));
    }

    @ParameterizedTest(name = "an unreadable setting [{0}] falls back to the default, never to zero")
    @CsvSource({"'', 10", "'   ', 10", "abc, 10", "-1, 10", "'7', 7", "'0', 0"})
    void settingsFallBackToTheDefaultNotZero(String raw, int expected) {
        // Zero means "no limit", so reading a typo as zero would quietly disable retention and
        // the database would start growing again with nothing saying so. The empty string is
        // the case that matters: parsed as a number it is zero, which is exactly wrong.
        assertThat(RetentionPolicy.intSetting(raw, 10)).isEqualTo(expected);
    }
}
