/**
 * Frameworks, statement of applicability, evidence, OWASP.
 *
 * <p><b>What it may use is declared here and verified by Spring Modulith</b> ({@code
 * ModularityTest}, decision 0030): a dependency on a module, or on a named interface ({@code
 * module::name}), missing from this list fails the build, and so does a line nothing uses. A domain
 * does not list the foundation, which is shared. Adding a line is a decision for the review that
 * needs it, with its reason written beside it — not the edit that turns the build green.
 *
 * <p>The top of the domains: an evidence bundle states what the modules below it recorded — the
 * model reviews ({@code ai}), the documents ({@code exports}), the verdicts ({@code gate}), the
 * components ({@code inventory}), the backlog ({@code issues} and {@code issues::queries}), the
 * figures ({@code posture}), the rule sets ({@code rules}), the scans ({@code scanning} and {@code
 * scanning::queries}) and the targets. Nothing uses it but {@code platform}.
 *
 * <p>{@code access::security} for its routes: the markers, the principal and {@code Visibilities},
 * which every controller needs. Only its {@code web} may name them — the layer rule keeps a
 * module's service layer off every {@code web} package, {@code access}'s included.
 */
@ApplicationModule(allowedDependencies = {
        "access", "access::security", "ai", "exports", "gate", "inventory", "issues", "issues::queries",
        "posture", "rules", "scanning", "scanning::queries", "targets"})
package com.asmolabs.vectispire.core.compliance;

import org.springframework.modulith.ApplicationModule;
