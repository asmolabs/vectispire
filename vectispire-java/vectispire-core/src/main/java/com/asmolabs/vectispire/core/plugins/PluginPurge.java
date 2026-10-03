package com.asmolabs.vectispire.core.plugins;

import com.asmolabs.vectispire.common.domain.targets.ScanTarget;
import com.asmolabs.vectispire.core.plugins.persistence.CoverageImportRepository;
import com.asmolabs.vectispire.core.plugins.persistence.CoveragePackageRepository;
import com.asmolabs.vectispire.core.plugins.persistence.PluginActivationRepository;
import com.asmolabs.vectispire.core.plugins.persistence.SarifImportRepository;
import com.asmolabs.vectispire.core.plugins.persistence.SarifSourceRepository;
import com.asmolabs.vectispire.core.plugins.persistence.TestReportImportRepository;
import com.asmolabs.vectispire.core.plugins.persistence.TestSuiteResultRepository;
import com.asmolabs.vectispire.core.targets.ProjectDeleted;
import com.asmolabs.vectispire.core.targets.TargetDeleted;
import com.asmolabs.vectispire.core.targets.TargetPurge;
import org.springframework.context.event.EventListener;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * The rows of this module that name a project or a repository going away, in the transaction that
 * deletes it.
 *
 * <p><b>Why listeners and not cascades.</b> The tables were written once, in a common migration, with
 * no foreign key — a key would have to be written three times (decision 0027). So nothing follows a
 * deleted project or repository into them, and without these listeners an activation or a source
 * would outlive its scope: inert while the identifier is unused, and attached to whatever took it if
 * an engine ever handed it out again.
 *
 * <p>Nothing here is referenced by another module's table, so the repository's rows go in the first
 * phase, with the other rows that name a target by identifier alone. Inside the module one row names
 * another — a test suite its import, a coverage package its import — and the children go first: their
 * delete finds them through the import rows, which must still be there.
 */
@Component
class PluginPurge {

    private final PluginActivationRepository activations;
    private final SarifSourceRepository sources;
    private final SarifImportRepository imports;
    private final CoverageImportRepository coverage;
    private final CoveragePackageRepository coveragePackages;
    private final TestReportImportRepository testReports;
    private final TestSuiteResultRepository suites;

    PluginPurge(
            PluginActivationRepository activations,
            SarifSourceRepository sources,
            SarifImportRepository imports,
            CoverageImportRepository coverage,
            CoveragePackageRepository coveragePackages,
            TestReportImportRepository testReports,
            TestSuiteResultRepository suites) {
        this.activations = activations;
        this.sources = sources;
        this.imports = imports;
        this.coverage = coverage;
        this.coveragePackages = coveragePackages;
        this.testReports = testReports;
        this.suites = suites;
    }

    /**
     * A repository's imports — SARIF, coverage and its packages, test reports and their suites — and the sources
     * declared for it alone. A container has none of them.
     */
    @EventListener
    @Order(TargetPurge.Phase.REFERENCES)
    @Transactional(propagation = Propagation.MANDATORY)
    public void purge(TargetDeleted deleted) {
        if (deleted.target() instanceof ScanTarget.Repository repository) {
            imports.deleteByRepository(repository.id());
            coveragePackages.deleteByRepository(repository.id());
            coverage.deleteByRepository(repository.id());
            suites.deleteByRepository(repository.id());
            testReports.deleteByRepository(repository.id());
            sources.deleteByRepository(repository.id());
        }
    }

    /** A project's activations, and the sources declared for it. */
    @EventListener
    @Transactional(propagation = Propagation.MANDATORY)
    public void purge(ProjectDeleted deleted) {
        activations.deleteByProject(deleted.projectId());
        sources.deleteByProject(deleted.projectId());
    }
}
