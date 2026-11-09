/**
 * The security event stream and its delivery through the outbox (decision 0025).
 *
 * <p><b>What it may use is declared here and verified by Spring Modulith</b> ({@code
 * ModularityTest}, decision 0030): a dependency on a module, or on a named interface ({@code
 * module::name}), missing from this list fails the build, and so does a line nothing uses. A domain
 * does not list the foundation, which is shared. Adding a line is a decision for the review that
 * needs it, with its reason written beside it — not the edit that turns the build green.
 *
 * <p>Nothing above the foundation for its services: it hears the audit log through {@code
 * AuditLogService.Listener} and the chain's {@code AuditChainBroken} event.
 *
 * <p>{@code access::security} for its routes: the markers, the principal and {@code Visibilities},
 * which every controller needs. Only its {@code web} may name them — the layer rule keeps a
 * module's service layer off every {@code web} package, {@code access}'s included.
 */
@ApplicationModule(allowedDependencies = {"access::security"})
package com.asmolabs.vectispire.core.siem;

import org.springframework.modulith.ApplicationModule;
