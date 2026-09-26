/**
 * The tracker client, the ticket links, the tracker's webhook and the ticket sweep.
 *
 * <p><b>What it may use is declared here and verified by Spring Modulith</b> ({@code
 * ModularityTest}, decision 0030): a dependency on a module, or on a named interface ({@code
 * module::name}), missing from this list fails the build, and so does a line nothing uses. A domain
 * does not list the foundation, which is shared. Adding a line is a decision for the review that
 * needs it, with its reason written beside it — not the edit that turns the build green.
 *
 * <p>{@code access}, {@code issues}, {@code targets}: a ticket is attached to a visible issue of a
 * target. {@code gate} since step 5 gave it the stored policies: the sweep opens a ticket only for
 * an issue the policy of its scope would fail on, and asks {@code ActiveGatePolicies} instead of
 * reading their table from below {@code gate}. {@code gate} uses nothing that uses {@code tickets}
 * — the tracker implements {@code issues}' {@code TicketReferences}.
 *
 * <p>{@code access::security} for its routes: the markers, the principal and {@code Visibilities},
 * which every controller needs. Only its {@code web} may name them — the layer rule keeps a
 * module's service layer off every {@code web} package, {@code access}'s included.
 */
@ApplicationModule(allowedDependencies = {"access", "access::security", "gate", "issues", "targets"})
package com.asmolabs.vectispire.core.tickets;

import org.springframework.modulith.ApplicationModule;
