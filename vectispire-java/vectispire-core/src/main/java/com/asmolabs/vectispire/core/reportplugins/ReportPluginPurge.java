package com.asmolabs.vectispire.core.reportplugins;

import com.asmolabs.vectispire.core.reportplugins.persistence.ReportPluginActivationRepository;
import com.asmolabs.vectispire.core.targets.ProjectDeleted;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * A project's report plugin activations, in the transaction that deletes the project (decision 0035 §4:
 * deleting a project takes its activations — and, once lots R3 and R4 add them, its runs and its documents).
 *
 * <p><b>A listener, not a cascade</b>: the table was written once, in a common migration, with no foreign key
 * (decision 0027). Without this an activation would outlive its project — inert while the identifier is
 * unused, and attached to whatever took it if an engine ever handed it out again. Nothing references these
 * rows, so no phase is needed.
 */
@Component
class ReportPluginPurge {

    private final ReportPluginActivationRepository activations;

    ReportPluginPurge(ReportPluginActivationRepository activations) {
        this.activations = activations;
    }

    @EventListener
    @Transactional(propagation = Propagation.MANDATORY)
    public void purge(ProjectDeleted deleted) {
        activations.deleteByProject(deleted.projectId());
    }
}
