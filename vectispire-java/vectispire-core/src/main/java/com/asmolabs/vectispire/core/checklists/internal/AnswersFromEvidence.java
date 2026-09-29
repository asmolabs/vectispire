package com.asmolabs.vectispire.core.checklists.internal;

import com.asmolabs.vectispire.core.checklists.ProjectChecklistService;
import com.asmolabs.vectispire.core.plugins.RepositoryReported;
import com.asmolabs.vectispire.core.scanning.RepositoryScanned;
import org.springframework.stereotype.Component;

/**
 * The checklists' side of the two ports below them: a completed scan ({@code scanning}) and an accepted
 * report ({@code plugins}) are new evidence about a repository, and the draft checklist of its project is
 * answered again from it (decision 0032, amendment "the scans answer the lines they measure").
 *
 * <p>A port each module declares rather than an event: the two owners sit below {@code checklists} and
 * may not name it, and the call is made after their own commit — a synchronous domain event is the
 * pattern for work that must share the publisher's transaction, which this must not. What the callers
 * guarantee, they guarantee themselves: they catch whatever is thrown here, so that a scan or an import
 * never fails because a checklist could not be answered.
 */
@Component
public class AnswersFromEvidence implements RepositoryScanned, RepositoryReported {

    private final ProjectChecklistService checklists;

    public AnswersFromEvidence(ProjectChecklistService checklists) {
        this.checklists = checklists;
    }

    @Override
    public void scanned(long repositoryId) {
        checklists.answerFromEvidence(repositoryId);
    }

    @Override
    public void reported(long repositoryId) {
        checklists.answerFromEvidence(repositoryId);
    }
}
