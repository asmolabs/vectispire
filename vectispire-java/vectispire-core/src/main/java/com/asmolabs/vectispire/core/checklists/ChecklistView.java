package com.asmolabs.vectispire.core.checklists;

import java.util.List;

/**
 * One revision of a project's checklist, whole: its header, its lines grouped as the template orders
 * them, and whether it may be submitted.
 *
 * @param projectName the product, as the header states it
 * @param answerWords the template's own words for yes, no and — if the version offers it — not
 *     applicable, as the importer mapped them
 * @param authors every account that wrote this revision — opened it, answered, carried or confirmed a
 *     line, attached or withdrew a proof, submitted it: with four-eyes on, none of them signs it off
 * @param fourEyesRequired whether four-eyes is on now, which decides whether an author may sign off
 * @param readyToSubmit a draft whose every line is ready
 */
public record ChecklistView(
        ChecklistRevisionSummary checklist,
        String projectName,
        boolean offersNotApplicable,
        AnswerWordsView answerWords,
        List<String> authors,
        boolean fourEyesRequired,
        boolean readyToSubmit,
        List<ChecklistLineView> lines) {

    public ChecklistView {
        authors = List.copyOf(authors);
        lines = List.copyOf(lines);
    }

    /** @param notApplicable null when the version does not offer "not applicable" */
    public record AnswerWordsView(String yes, String no, String notApplicable) {}
}
