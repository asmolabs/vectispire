package com.asmolabs.vectispire.core.checklists;

import java.time.Instant;
import java.util.List;

/**
 * The measured lines of one revision, each beside its answer (decision 0032 §6): what the rules find
 * now for a draft or a submitted revision, what was frozen with a signed-off one.
 *
 * <p>Only the lines bound to a rule are here; every other line is "not measured here".
 *
 * @param live whether the measurements were computed for this read — a draft's or a submitted
 *     revision's — rather than read back as stored: a signed-off revision's are the sign-off's, frozen
 *     with it, and a superseded one's are the last stored, or none
 * @param computedAt the instant of this read's computation; null when nothing was computed
 */
public record ChecklistMeasurementsView(
        long projectId, int revision, String status, boolean live, Instant computedAt, List<MeasuredLineView> lines) {

    public ChecklistMeasurementsView {
        lines = List.copyOf(lines);
    }

    /**
     * One bound line.
     *
     * @param rule the rule the line is measured by, in the binding's shape
     * @param answer the current answer's value, null while the line is unanswered
     * @param measurement what the rule finds — now, or as frozen; null for a superseded revision that
     *     never stored one
     * @param atSubmission what it found at the submission, for a submitted or signed-off revision; null
     *     otherwise — a sign-off is refused when the two differ
     * @param reconciliation {@code consistent}, {@code contradicted}, {@code declared_not_measured},
     *     {@code understated}, {@code excluded}, {@code unanswered}
     * @param problems what the measurement keeps from a submission: {@code measurement_contradicted} for a
     *     "yes" against a failure, {@code comment_required} and {@code evidence_required} or {@code
     *     evidence_expired} for a "yes" where there is no data; empty when it keeps nothing
     */
    public record MeasuredLineView(
            long itemId,
            int position,
            String itemKey,
            ChecklistRuleForm rule,
            String answer,
            Long answerId,
            ChecklistMeasurementView measurement,
            ChecklistMeasurementView atSubmission,
            String reconciliation,
            List<String> problems) {

        public MeasuredLineView {
            problems = List.copyOf(problems);
        }
    }
}
