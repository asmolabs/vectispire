package com.asmolabs.vectispire.core.checklists;

import java.util.Locale;

/**
 * What keeps a line from a submission, in the order a person fixes them — the tokens of a line's {@code
 * problems}, of a {@code checklist-incomplete} refusal's lines and of a measured line's.
 *
 * <p>A type rather than six string literals, because the OpenAPI document enumerates them from here
 * ({@code ChecklistVocabularies}) and a client's union is only as complete as that list.
 */
enum LineProblem {
    UNANSWERED,
    AWAITING_CONFIRMATION,
    /** A "yes" against a failing measurement (decision 0032, question 3) — refused at submission. */
    MEASUREMENT_CONTRADICTED,
    COMMENT_REQUIRED,
    EVIDENCE_REQUIRED,
    EVIDENCE_EXPIRED;

    String wireName() {
        return name().toLowerCase(Locale.ROOT);
    }

    /** What a missing measurement asks of a "yes" (question 4): its comment and a proof in date. */
    boolean askedWhereNoData() {
        return this == COMMENT_REQUIRED || this == EVIDENCE_REQUIRED || this == EVIDENCE_EXPIRED;
    }
}
