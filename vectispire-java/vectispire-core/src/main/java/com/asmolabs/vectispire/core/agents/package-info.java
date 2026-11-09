/**
 * Agent administration, the agent row, and the agent protocol.
 *
 * <p><b>What it may use is declared here and verified by Spring Modulith</b> ({@code
 * ModularityTest}, decision 0030): a dependency on a module, or on a named interface ({@code
 * module::name}), missing from this list fails the build, and so does a line nothing uses. A domain
 * does not list the foundation, which is shared. Adding a line is a decision for the review that
 * needs it, with its reason written beside it — not the edit that turns the build green.
 *
 * <p>{@code access}: an agent key is issued and revoked through {@code AgentKeys}, and the
 * principal holds {@code AgentView}. {@code scanning} and {@code targets}: the protocol claims
 * scans and hands over their targets. {@code rules} since agents became a module and took its
 * controllers: a remote agent fetches the rule set a task names by its hash. None of them uses
 * {@code agents}: {@code access} and {@code scanning} reach the agent row through the ports {@code
 * AgentDirectory} and {@code AgentClaimLock}, implemented here.
 *
 * <p>{@code access::security} for its routes: the markers, the principal and {@code Visibilities},
 * which every controller needs. Only its {@code web} may name them — the layer rule keeps a
 * module's service layer off every {@code web} package, {@code access}'s included.
 */
@ApplicationModule(allowedDependencies = {"access", "access::security", "rules", "scanning", "targets"})
package com.asmolabs.vectispire.core.agents;

import org.springframework.modulith.ApplicationModule;
