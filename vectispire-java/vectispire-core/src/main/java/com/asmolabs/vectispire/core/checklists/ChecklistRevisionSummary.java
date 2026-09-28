package com.asmolabs.vectispire.core.checklists;

import java.time.Instant;

/**
 * One revision of a project's checklist as a listing shows it: where it stands, which template version
 * it answers, and who moved it through its life (decision 0032 §5).
 *
 * @param revision the revision's number within the project, what the routes name
 * @param edition the writes counted on it so far: every write names the edition its writer read
 * @param author the account responsible for it, the header's author — whoever opened it
 * @param supersedesRevision the revision it was opened from, by a move to another version or a reopening
 * @param signOffFourEyes whether four-eyes required the signer to differ from its authors; null until
 *     signed off
 */
public record ChecklistRevisionSummary(
        long projectId,
        int revision,
        String status,
        int edition,
        String templateSlug,
        String templateName,
        int versionOrdinal,
        String versionLabel,
        String author,
        Instant openedAt,
        String openedBy,
        Integer supersedesRevision,
        Instant submittedAt,
        String submittedBy,
        Instant returnedAt,
        String returnedBy,
        String returnReason,
        Instant signedOffAt,
        String signedOffBy,
        Boolean signOffFourEyes,
        Instant supersededAt,
        String supersededBy) {}
