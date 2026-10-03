/**
 * Report plugins (decision 0035) — so far its first lot: a project's export, the {@code
 * vectispire-project-export} document a plugin will receive, built for a caller who sees the whole
 * project, signed, and served on its own so an organisation can write its plugin against its own data.
 *
 * <p><b>What it may use is declared here and verified by Spring Modulith</b> ({@code ModularityTest},
 * decision 0030): a dependency on a module, or on a named interface ({@code module::name}), missing from
 * this list fails the build, and so does a line nothing uses. A domain does not list the foundation, which
 * is shared — the audit log, the settings ({@code ProductVersion}, the branding, the public URL), the
 * signing key. Above every module it reads, and used by nobody but {@code platform}: an export states what
 * the modules below it recorded.
 *
 * <p>{@code access}: the export is refused here, in the service, through {@code
 * RowVisibility.requireEveryTargetOfProject} — the whole project, images included, or the 404 of an absent
 * one — and the requester's role is checked here too (write accounts and auditors, decision 0035 answer 4).
 * {@code AccountNames} turns the user names the rows record into display names, never an e-mail address.
 *
 * <p>{@code access::security} for its routes: the markers, the principal and {@code RequestActors}.
 *
 * <p>Each part of the export is read from its owner, through a method of its owner's API — never a
 * repository of theirs, nor a statement naming their entities:
 *
 * <ul>
 *   <li>{@code targets}: the project, its solution and the targets filed in it ({@code SolutionQueryService},
 *       {@code TargetCatalog});
 *   <li>{@code scanning}, {@code scanning::queries}: each target's newest completed scan ({@code
 *       NewestCompletedScanRow}, a published query record) and its outline ({@code ScanCatalog});
 *   <li>{@code gate}: each target's last recorded verdict ({@code GateRegisterService});
 *   <li>{@code issues}, {@code issues::queries}: the backlog through {@code IssueFilters}, its counts, the
 *       remediation windows ({@code IssueCatalog}, {@code SlaService});
 *   <li>{@code inventory}: the consolidated components ({@code ConsolidatedInventoryService});
 *   <li>{@code compliance}: the project's compliance state ({@code ComplianceService}) — in the export by
 *       the owner's answer 8;
 *   <li>{@code checklists}: the signed-off statements and the open one ({@code ChecklistDocumentService}).
 * </ul>
 */
@ApplicationModule(allowedDependencies = {
        "access", "access::security", "targets", "scanning", "scanning::queries", "gate", "issues",
        "issues::queries", "inventory", "compliance", "checklists"})
package com.asmolabs.vectispire.core.reportplugins;

import org.springframework.modulith.ApplicationModule;
