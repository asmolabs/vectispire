/**
 * Forges (decision 0037): read-only connections to GitHub and GitLab from which repositories are discovered
 * and imported as ordinary targets. Lots D1 to D3 and D5 to D6: the connections — the token probed against the
 * forge through the outbound guard, its scopes judged against an allow-list, stored encrypted with its row as
 * context, never returned — the discoveries, queued, claimed by a control-plane instance under a lease, listed
 * page by page through the outbound pager and kept as a snapshot compared run to run; the selection over that
 * snapshot, its preview, and the import, with the provenance of each imported target.
 *
 * <p><b>What it may use is declared here and verified by Spring Modulith</b> ({@code ModularityTest},
 * decision 0030): a dependency on a module, or on a named interface ({@code module::name}), missing from
 * this list fails the build, and so does a line nothing uses. A domain does not list the foundation, which
 * is shared — the outbound door ({@code OutboundJson}), the encryption, the audit log. Used by nobody but
 * {@code platform}: {@code targets} never learns that a target was imported — the dependency runs one way.
 *
 * <p>{@code targets} for the import (lot D6): the targets, solutions and projects are created through its own
 * gestures ({@code TargetImports}, {@code RepositoryAdministrationService}, {@code SolutionAdministrationService}) —
 * the same refusals and entries as the forms — the first scans queued through {@code TargetScans}, the clone
 * credentials listed by {@code GitTokenAdministrationService} and {@code SshKeyAdministrationService}, the default
 * schedule read from {@code TargetSchedules}, and the provenance link dropped when it hears {@code TargetDeleted}.
 *
 * <p>{@code access::security} for its routes alone: the markers, the principal and {@code RequestActors}.
 * Its services decide nothing about who the caller is — the routes are administrators' and name no target
 * ({@code ArchitectureTest.accessForRoutesOnly}).
 */
@ApplicationModule(allowedDependencies = {"targets", "access::security"})
package com.asmolabs.vectispire.core.forges;

import org.springframework.modulith.ApplicationModule;
