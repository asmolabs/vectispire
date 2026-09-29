package com.asmolabs.vectispire.core.checklists;

import java.util.List;

/**
 * One line of a project's checklist: the template's words, the current answer, the proofs, and what
 * still stands between the line and a submission.
 *
 * @param itemId the template item the line answers — what the line's routes name
 * @param rule the rule the line is measured by, null for a line measured by none — its measurement is
 *     read from the revision's measurements route
 * @param answer the newest answer, null while the line is unanswered; its {@code measurementId} names the
 *     measurement it rests on, when it rests on one
 * @param evidence every proof attached in this revision, withdrawn ones included, oldest first
 * @param edition the revision's edition at which the line last changed — an answer, a proof, a
 *     withdrawal; a write on the line naming an older edition is refused as stale
 * @param problems what keeps the line from a submission, in the order a person fixes them: {@code
 *     unanswered}, {@code awaiting_confirmation}, {@code comment_required}, {@code evidence_required},
 *     {@code evidence_expired}; empty when the line is ready
 */
public record ChecklistLineView(
        Long itemId,
        String itemKey,
        Integer position,
        String domain,
        String objective,
        String control,
        String contact,
        String kpi,
        String evidenceKind,
        Integer evidenceValidityMonths,
        ChecklistRuleForm rule,
        ChecklistAnswerView answer,
        List<ChecklistEvidenceView> evidence,
        int edition,
        List<String> problems) {

    public ChecklistLineView {
        evidence = List.copyOf(evidence);
        problems = List.copyOf(problems);
    }
}
