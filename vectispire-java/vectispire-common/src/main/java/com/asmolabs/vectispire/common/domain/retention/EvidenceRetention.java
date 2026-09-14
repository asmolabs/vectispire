package com.asmolabs.vectispire.common.domain.retention;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * How long the registers that <em>prove a control ran</em> are kept.
 *
 * <p><b>A different question from {@link RetentionPolicy}, which is why it is a different
 * setting.</b> That one bounds the growth of raw scanner payloads: megabytes per scan, and
 * reproducible — rescan the target and Syft says the same thing again. This one bounds a gate
 * verdict: a few hundred bytes, and <em>not</em> reproducible, because it records that a
 * pipeline asked on a given day and was refused. Nothing can recreate it afterwards.
 *
 * <p>Both were on {@code retention_max_age_days} until an auditor's calendar made the conflict
 * plain. A certification cycle is annual — the assessor asks for evidence covering the audited
 * period, and arrives some weeks after it closes. Ninety days of payload retention is generous;
 * ninety days of verdict retention deletes the proof nine months before anyone asks for it, and
 * silently, since the register looks healthy right up to the visit.
 */
public final class EvidenceRetention {

    /**
     * Twelve months, plus the gap between the end of a period and the assessor reading it.
     *
     * <p>Not a round year: an audit covering a calendar year is rarely conducted inside it. The
     * extra five weeks are what keeps January's verdicts readable at the February visit.
     */
    public static final Duration DEFAULT = Duration.ofDays(400);

    /** Zero keeps evidence for ever — the safe direction for this particular table. */
    public static final int UNLIMITED = 0;

    private EvidenceRetention() {}

    /**
     * The instant before which a verdict may be purged, or empty when retention is unlimited.
     *
     * @param days the configured window; zero or negative disables purging entirely
     * @param now the clock's reading
     */
    public static Optional<Instant> cutoff(int days, Instant now) {
        return days <= UNLIMITED ? Optional.empty() : Optional.of(now.minus(Duration.ofDays(days)));
    }
}
