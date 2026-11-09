package com.asmolabs.vectispire.core.checklists;

import java.util.List;

/**
 * Everything written on one line of one revision, oldest first: every answer with its author and
 * instant — the current one last — and every proof, withdrawn ones included (decision 0032 §5).
 */
public record ChecklistLineHistory(
        long projectId, int revision, long itemId, List<ChecklistAnswerView> answers,
        List<ChecklistEvidenceView> evidence) {

    public ChecklistLineHistory {
        answers = List.copyOf(answers);
        evidence = List.copyOf(evidence);
    }
}
