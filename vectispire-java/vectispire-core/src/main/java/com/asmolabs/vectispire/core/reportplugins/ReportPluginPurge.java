package com.asmolabs.vectispire.core.reportplugins;

import com.asmolabs.vectispire.core.reportplugins.persistence.ReportExportRepository;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportPluginActivationRepository;
import com.asmolabs.vectispire.core.reportplugins.persistence.ReportRunRepository;
import com.asmolabs.vectispire.core.targets.ProjectDeleted;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * A project's report plugin activations, runs and their exports, in the transaction that deletes the project
 * (decision 0035 §4: deleting a project takes its activations, its runs and its documents — lot R4 adds the
 * documents).
 *
 * <p><b>A listener, not a cascade</b>: the tables were written once, in common migrations, with no foreign key
 * (decision 0027). Without this an activation would outlive its project — inert while the identifier is unused,
 * and attached to whatever took it if an engine ever handed it out again — and a run would keep a whole project's
 * export after the project was gone. The exports first: they are found through their runs.
 */
@Component
class ReportPluginPurge {

    private final ReportPluginActivationRepository activations;
    private final ReportRunRepository runs;
    private final ReportExportRepository exports;

    ReportPluginPurge(ReportPluginActivationRepository activations, ReportRunRepository runs,
            ReportExportRepository exports) {
        this.activations = activations;
        this.runs = runs;
        this.exports = exports;
    }

    @EventListener
    @Transactional(propagation = Propagation.MANDATORY)
    public void purge(ProjectDeleted deleted) {
        exports.deleteByProject(deleted.projectId());
        runs.deleteByProject(deleted.projectId());
        activations.deleteByProject(deleted.projectId());
    }
}
