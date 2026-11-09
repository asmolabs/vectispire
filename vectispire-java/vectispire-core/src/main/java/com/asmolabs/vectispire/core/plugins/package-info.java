/**
 * Plugins — third-party analysers run as containers, emitting SARIF — their activation per project,
 * and the reports declared internal sources send: SARIF (decision 0017, amended), coverage and test
 * reports (decision 0032 §7), and build SBOMs (decision 0039).
 *
 * <p><b>What it may use is declared here and verified by Spring Modulith</b> ({@code
 * ModularityTest}, decision 0030): a dependency on a module, or on a named interface ({@code
 * module::name}), missing from this list fails the build, and so does a line nothing uses. A domain
 * does not list the foundation, which is shared. Adding a line is a decision for the review that
 * needs it, with its reason written beside it — not the edit that turns the build green.
 *
 * <p>{@code scanning}: a scan asks which plugins a repository runs and fetches a manifest by
 * reference through {@code ScanPlugins}, a port {@code scanning} declares and this module implements —
 * the {@code ScanRuleSets} shape, so the dependency points from here to {@code scanning}. {@code
 * issues}: an import folds its findings into the backlog through {@code IssueSyncService.syncImport},
 * the reconciliation a scan uses, so an imported issue is resolved, reopened and fingerprinted by the
 * same rules. {@code targets}: an activation and a source name a project or a repository, checked
 * through {@code SolutionAdministrationService} and {@code TargetCatalog}, and purged on {@code
 * ProjectDeleted} and {@code TargetDeleted}, which {@code targets} publishes. {@code access}: a source
 * is bound to an integration key checked through {@code ApiKeyAdministrationService}, which also names
 * the keys the source list shows its governance readers, and the routes
 * resolve the caller's visibility through {@code VisibilityService}. {@code inventory}: a build SBOM
 * admitted here is kept and completes the repository's scans through {@code BuildSbomInventory}, which
 * owns the components — the declared source, the key and the audit stay this module's, as for the other
 * imports (decision 0039).
 *
 * <p>{@code access::security} for its routes: the markers, the principal and {@code Visibilities},
 * which every controller needs. Only its {@code web} may name them — the layer rule keeps a
 * module's service layer off every {@code web} package, {@code access}'s included.
 */
@ApplicationModule(allowedDependencies = {
        "access", "access::security", "inventory", "issues", "scanning", "targets"})
package com.asmolabs.vectispire.core.plugins;

import org.springframework.modulith.ApplicationModule;
