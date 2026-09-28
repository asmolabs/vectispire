/**
 * Security checklists — the organisation's templates, their versions and their items, imported from
 * its own workbooks, and each project's checklist answered against them by people, with its proofs,
 * its submission and its sign-off (decision 0032). The measurements are a later lot of the same
 * module.
 *
 * <p><b>What it may use is declared here and verified by Spring Modulith</b> ({@code
 * ModularityTest}, decision 0030): a dependency on a module, or on a named interface ({@code
 * module::name}), missing from this list fails the build, and so does a line nothing uses. A domain
 * does not list the foundation, which is shared — the audit log, the settings (four-eyes on
 * publishing) — so the list names only what the lots so far use. Decision 0032 §1 tabulates what the
 * later lots will add, each with its reason: {@code scanning}, {@code issues}, {@code plugins},
 * {@code inventory}. Each is added by the lot that first uses it, in its review, not ahead of it.
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
 * and files of a project are purged in the transaction that deletes it (open question 10).
 */
@ApplicationModule(allowedDependencies = {"access", "access::security", "targets"})
package com.asmolabs.vectispire.core.checklists;

import org.springframework.modulith.ApplicationModule;
