/**
 * Security checklists — the organisation's templates, their versions and their items, imported from
 * its own workbooks, and each project's checklist answered against them by people — and on its measured
 * lines by Vectispire, from the scans and imports it is told of ({@code RepositoryScanned}, {@code
 * RepositoryReported}, ports of {@code scanning} and {@code plugins} it implements) — with its proofs,
 * its submission and its sign-off, and the measurements a line's rule takes of the project (decision
 * 0032).
 *
 * <p><b>What it may use is declared here and verified by Spring Modulith</b> ({@code
 * ModularityTest}, decision 0030): a dependency on a module, or on a named interface ({@code
 * module::name}), missing from this list fails the build, and so does a line nothing uses. A domain
 * does not list the foundation, which is shared — the audit log, the settings (four-eyes on
 * publishing) — so the list names only what the module uses, each line added by the lot that first
 * needed it, in its review (decision 0032 §1 tabulates them).
 *
 * <p>{@code access}: the routes hand the services the signed-in account, {@code UserView}, whose id
 * four-eyes compares with a draft's or a revision's authors — an account, never a name taken from the
 * request — and the caller's {@code VisibilityService.Allowance}. The project checklists' service
 * refuses a project through {@code RowVisibility.requireWhollyVisibleProject}, the whole-project guard
 * (§8): {@code checklists} is not one of the modules that use {@code access} for their routes only.
 *
 * <p>{@code access::security} for its routes: the markers, the principal and {@code RequestActors},
 * which every controller needs. A template is the organisation's and names no target, so its routes
 * resolve no visibility and the roles decide — {@code @RequiresSecurityLead} writes a template,
 * {@code @RequiresGovernanceRead} reads one. A project's checklist names a project, and each of its
 * routes resolves the caller's allowance for the service to refuse it.
 *
 * <p>{@code targets} (project checklists): the project a checklist answers for and the repositories
 * filed in it now, which the whole-project guard compares with the caller's visibility ({@code
 * SolutionQueryService.members}); and {@code ProjectDeleted}, on which the checklists, answers, proofs
 * and files of a project are purged in the transaction that deletes it (open question 10). The
 * measurements read each repository's schedule too, through {@code TargetCatalog} and {@code
 * CronExpressions}, the scheduler's own parser — a dependency rule asking for a matching schedule.
 *
 * <p>The measurements (§6) read the evidence from its owners, each through a method of its own API,
 * never a repository of theirs nor a statement naming their entities:
 *
 * <ul>
 *   <li>{@code scanning}, {@code scanning::queries}: {@code ScanCatalog} — the newest scan in which a
 *       built-in step produced ({@code ExaminingScanRow}, a published query record), the completed
 *       scans within an age and the unrecorded among them, each plugin's state per scan;
 *   <li>{@code issues}: {@code IssueCatalog} — the backlog of a scope counted per repository, severity
 *       and state, settled triage left out by the owner's {@code not in};
 *   <li>{@code plugins}: {@code ReportImportCatalog} — the newest SARIF import carrying a tool, the
 *       newest coverage and test report (§7);
 *   <li>{@code inventory}: {@code ComponentCatalog} — the components of the newest analysed SBOM, for
 *       the component rule.
 * </ul>
 */
@ApplicationModule(allowedDependencies = {
        "access", "access::security", "targets", "scanning", "scanning::queries", "issues", "plugins", "inventory"})
package com.asmolabs.vectispire.core.checklists;

import org.springframework.modulith.ApplicationModule;
