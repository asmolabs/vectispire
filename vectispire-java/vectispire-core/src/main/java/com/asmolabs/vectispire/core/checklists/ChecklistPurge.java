package com.asmolabs.vectispire.core.checklists;

import com.asmolabs.vectispire.core.checklists.persistence.ChecklistAnswerRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistEvidenceRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistFileRepository;
import com.asmolabs.vectispire.core.checklists.persistence.ChecklistRepository;
import com.asmolabs.vectispire.core.targets.ProjectDeleted;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * A project's checklists, their answers, proofs and files, in the transaction that deletes it
 * (decision 0032, open question 10). The audit entries stay: they record what was attested, and by
 * whom, after the project is gone.
 *
 * <p><b>Why a listener and not a cascade.</b> The tables were written once, in a common migration,
 * with no foreign key — a key would have to be written three times (decision 0027) — so nothing
 * follows a deleted project into them. Left behind, a checklist would name a project nobody can see,
 * and should an engine hand the identifier out again, the next project would open with somebody
 * else's signed-off answers and their files.
 *
 * <p><b>Children first, though no key asks it</b>: the answers and proofs are found through their
 * checklists' rows, which must still be there when those two statements run; the files are found by
 * their own project column.
 */
@Component
class ChecklistPurge {

    private final ChecklistRepository checklists;
    private final ChecklistAnswerRepository answers;
    private final ChecklistEvidenceRepository evidence;
    private final ChecklistFileRepository files;

    ChecklistPurge(
            ChecklistRepository checklists,
            ChecklistAnswerRepository answers,
            ChecklistEvidenceRepository evidence,
            ChecklistFileRepository files) {
        this.checklists = checklists;
        this.answers = answers;
        this.evidence = evidence;
        this.files = files;
    }

    @EventListener
    @Transactional(propagation = Propagation.MANDATORY)
    public void purge(ProjectDeleted deleted) {
        answers.deleteByProject(deleted.projectId());
        evidence.deleteByProject(deleted.projectId());
        files.deleteByProject(deleted.projectId());
        checklists.deleteByProject(deleted.projectId());
    }
}
