/**
 * The gate, its register, its stored policies and {@code ActiveGatePolicies}.
 *
 * <p><b>What it may use is declared here and verified by Spring Modulith</b> ({@code
 * ModularityTest}, decision 0030): a dependency on a module, or on a named interface ({@code
 * module::name}), missing from this list fails the build, and so does a line nothing uses. A domain
 * does not list the foundation, which is shared. Adding a line is a decision for the review that
 * needs it, with its reason written beside it — not the edit that turns the build green.
 *
 * <p>{@code issues} (and {@code issues::queries}' {@code IssueRows}), {@code scanning} (and {@code
 * scanning::queries}' {@code LatestScanRow}), {@code targets}: a verdict is computed over the open
 * issues and the latest scans of the targets, and the register takes its part of a deleted target's
 * purge. {@code rules}: the verdict weighs rule coverage ({@code RuleCoverageService}). {@code
 * siem}: a failed gate is a security event ({@code SECURITY_GATE_FAILED}). Not {@code access} for
 * its services since step 5: the register was purged past the evidence window by the authentication
 * tables' pass, through a port {@code gate} implemented; it is {@code gate}'s own periodic task now
 * ({@code VerdictRetentionTask}).
 *
 * <p>{@code access} for its routes only, which resolve a {@code Visibility} ({@code
 * ArchitectureTest.accessForRoutesOnly}).
 *
 * <p>{@code access::security} for its routes: the markers, the principal and {@code Visibilities},
 * which every controller needs. Only its {@code web} may name them — the layer rule keeps a
 * module's service layer off every {@code web} package, {@code access}'s included.
 */
@ApplicationModule(allowedDependencies = {
        "access", "access::security", "issues", "issues::queries", "rules", "scanning", "scanning::queries",
        "siem", "targets"})
package com.asmolabs.vectispire.core.gate;

import org.springframework.modulith.ApplicationModule;
