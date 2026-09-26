/**
 * Figures of risk: dashboard, scorecards, debt, quality, remediation, attack paths, the weekly
 * digest.
 *
 * <p><b>What it may use is declared here and verified by Spring Modulith</b> ({@code
 * ModularityTest}, decision 0030): a dependency on a module, or on a named interface ({@code
 * module::name}), missing from this list fails the build, and so does a line nothing uses. A domain
 * does not list the foundation, which is shared. Adding a line is a decision for the review that
 * needs it, with its reason written beside it — not the edit that turns the build green.
 *
 * <p>It reads what the modules below it hold — {@code gate}'s register, {@code inventory}'s
 * components, {@code issues}' backlog (and {@code issues::queries}), {@code scanning}'s scans,
 * {@code targets}' names — and sends the digest through {@code notifications}. {@code access}:
 * every figure is narrowed to what the account may see.
 *
 * <p>{@code access::security} for its routes: the markers, the principal and {@code Visibilities},
 * which every controller needs. Only its {@code web} may name them — the layer rule keeps a
 * module's service layer off every {@code web} package, {@code access}'s included.
 */
@ApplicationModule(allowedDependencies = {
        "access", "access::security", "gate", "inventory", "issues", "issues::queries", "notifications",
        "scanning", "targets"})
package com.asmolabs.vectispire.core.posture;

import org.springframework.modulith.ApplicationModule;
