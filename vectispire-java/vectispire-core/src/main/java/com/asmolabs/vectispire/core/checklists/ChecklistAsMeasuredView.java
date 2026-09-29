package com.asmolabs.vectispire.core.checklists;

import java.util.List;

/**
 * What answering every measured line as measured did (decision 0032 §6): the revision as it is after
 * the act, the lines it answered and those it left alone, with why.
 *
 * @param checklist the revision after the act, as every other write returns it
 * @param answered the lines answered, in the checklist's order — each the caller's "yes", resting on
 *     the measurement it was answered by; empty when there was nothing to answer, and then nothing was
 *     written and the edition did not move
 * @param skipped every other measured line, in the checklist's order
 */
public record ChecklistAsMeasuredView(ChecklistView checklist, List<AsMeasuredAnswer> answered,
        List<AsMeasuredSkip> skipped) {

    public ChecklistAsMeasuredView {
        answered = List.copyOf(answered);
        skipped = List.copyOf(skipped);
    }

    /**
     * One line answered.
     *
     * @param value the answer recorded — {@code yes}, the only one this act gives
     * @param answerId the answer's row, a line of the line's history
     * @param measurementId the measurement it rests on, stored with it
     * @param evidenceDigest that measurement's {@code evidenceDigest}
     */
    public record AsMeasuredAnswer(long itemId, int position, String value, long answerId, long measurementId,
            String evidenceDigest) {}

    /**
     * One line left alone.
     *
     * @param reason {@code already_answered}, {@code no_data} or {@code needs_comment} — a failing
     *     measurement, whose "no" the person answers with its comment, one line at a time
     * @param outcome the measurement's outcome: {@code pass}, {@code fail} or {@code no_data}
     * @param noDataReason why it has no data, null unless the outcome is {@code no_data}
     * @param answer the line's current answer, null unless the reason is {@code already_answered}
     */
    public record AsMeasuredSkip(long itemId, int position, String reason, String outcome, String noDataReason,
            String answer) {}
}
