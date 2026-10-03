/**
 * Forges (decision 0037): read-only connections to GitHub and GitLab from which repositories are discovered
 * and imported as ordinary targets. So far its first lot, D1: the connections — the token probed against
 * the forge through the outbound guard, its scopes judged against an allow-list, stored encrypted with its
 * row as context, never returned.
 *
 * <p><b>What it may use is declared here and verified by Spring Modulith</b> ({@code ModularityTest},
 * decision 0030): a dependency on a module, or on a named interface ({@code module::name}), missing from
 * this list fails the build, and so does a line nothing uses. A domain does not list the foundation, which
 * is shared — the outbound door ({@code OutboundJson}), the encryption, the audit log. Used by nobody but
 * {@code platform}: {@code targets} never learns that a target was imported, and the dependency the import
 * will add (lot D6) runs one way.
 *
 * <p>{@code access::security} for its routes alone: the markers, the principal and {@code RequestActors}.
 * Its services decide nothing about who the caller is — the routes are administrators' and name no target
 * ({@code ArchitectureTest.accessForRoutesOnly}).
 */
@ApplicationModule(allowedDependencies = {"access::security"})
package com.asmolabs.vectispire.core.forges;

import org.springframework.modulith.ApplicationModule;
