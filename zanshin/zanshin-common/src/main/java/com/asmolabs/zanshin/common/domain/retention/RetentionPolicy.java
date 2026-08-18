package com.asmolabs.zanshin.common.domain.retention;

import com.asmolabs.zanshin.common.domain.targets.ScanTarget;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The retention policy for raw scanner payloads.
 *
 * <p>A scan's {@code sbom} and {@code cves} carry the tools' untouched output. A container scan
 * of a JRE image weighs around 2.5 MB of SBOM, and nothing ever deleted anything: the database
 * grows for as long as the scheduler runs.
 *
 * <p><b>What is purged and what is kept is the whole subject.</b>
 *
 * <ul>
 *   <li><em>Purged</em>: the raw blobs. They exist for audit — "what exactly did Syft report
 *       that day" — and that value decays quickly.
 *   <li><em>Kept, always</em>: the summary and the finding count that the history displays,
 *       every finding, every issue. <b>The normalized projection is the durable record</b>,
 *       which is what it was built for, so purging a blob costs no history, no triage, no delta.
 * </ul>
 *
 * <p><b>The two rules combine, they do not add up.</b> A scan is purgeable only if it is
 * <em>both</em> outside the "last N of this target" window <em>and</em> older than the age
 * limit. Requiring both is what lets a target scanned twice a year keep its payloads while a
 * target scanned hourly stays bounded — neither rule alone does that.
 */
public record RetentionPolicy(int keepPerTarget, Duration maxAge) {

    /**
     * Keep the raw output of each target's last ten scans, and of anything under ninety days
     * old.
     *
     * <p>Generous on purpose: the goal is to bound growth, not to be stingy, and an operator
     * investigating a regression looks at recent scans.
     */
    public static final RetentionPolicy DEFAULT = new RetentionPolicy(10, Duration.ofDays(90));

    /** Zero on one axis means "no limit on that axis"; zero on both disables purging. */
    public static final int UNLIMITED = 0;

    /** A disabled policy purges nothing at all. */
    public boolean isEnabled() {
        return keepPerTarget != UNLIMITED || !maxAge.isZero();
    }

    /** The instant before which a scan is old enough to purge, or empty when unlimited. */
    public Optional<Instant> cutoff(Instant now) {
        return maxAge.isZero() ? Optional.empty() : Optional.of(now.minus(maxAge));
    }

    /**
     * @param createdAt when the scan ran; the ordering key as well as the age
     */
    public record Candidate(long scanId, ScanTarget target, Instant createdAt) {}

    /**
     * The scans whose raw payloads can be dropped.
     *
     * <p>Candidates must arrive <b>newest first, target by target</b>: that order is what gives
     * the rank its meaning, and a different sort would purge the most recent scans — precisely
     * the ones the payloads exist for. The caller owns the query, so the caller owns that
     * ordering; this cannot check it, and getting it wrong is silent.
     */
    public List<Long> prunable(List<Candidate> candidates, Instant now) {
        if (!isEnabled()) {
            return List.of();
        }

        Optional<Instant> cutoff = cutoff(now);
        Map<ScanTarget, Integer> rankPerTarget = new HashMap<>();
        List<Long> purgeable = new ArrayList<>();

        for (Candidate candidate : candidates) {
            int rank = rankPerTarget.merge(candidate.target(), 1, Integer::sum) - 1;

            boolean withinKeepWindow = keepPerTarget != UNLIMITED && rank < keepPerTarget;
            // `orElse(false)`, and the inversion is not obvious: with no age limit the age
            // protects nothing, so the keep window decides alone. Reading an absent cutoff as
            // "everything is recent" would make an unlimited age disable purging entirely —
            // the opposite of what "no limit on that axis" means.
            boolean recentEnough = cutoff.map(candidate.createdAt()::isAfter).orElse(false);
            if (withinKeepWindow || recentEnough) {
                continue;
            }
            purgeable.add(candidate.scanId());
        }
        return purgeable;
    }

    /**
     * An integer setting, or its default.
     *
     * <p>An unreadable value falls back to the default and <b>never to zero</b>: zero means "no
     * limit", so a typo in the settings would quietly disable retention and the database would
     * start growing again with nothing saying so. The empty string is the case that matters —
     * parsing it as a number gives zero in most languages, which is exactly the wrong answer.
     */
    public static int intSetting(String raw, int fallback) {
        if (raw == null || raw.isBlank()) {
            return fallback;
        }
        try {
            int value = Integer.parseInt(raw.trim());
            return value < 0 ? fallback : value;
        } catch (NumberFormatException notANumber) {
            return fallback;
        }
    }
}
