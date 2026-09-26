/**
 * Repositories, containers, solutions and projects, clone credentials, deletion — and the {@code
 * TargetDeleted} event and {@code TargetPurge} phases every owner of a target's rows listens to.
 *
 * <p><b>What it may use is declared here and verified by Spring Modulith</b> ({@code
 * ModularityTest}, decision 0030): a dependency on a module, or on a named interface ({@code
 * module::name}), missing from this list fails the build, and so does a line nothing uses. A domain
 * does not list the foundation, which is shared. Adding a line is a decision for the review that
 * needs it, with its reason written beside it — not the edit that turns the build green.
 *
 * <p>{@code access} alone: grants are revoked through {@code TargetGrants} before the purge's first
 * phase, and visibility reads the projects through {@code GrantableTargets}, a port {@code access}
 * declares and {@code targets} implements. Not {@code scanning}, nor {@code issues} (step 5): the
 * listings' figures and the scan trigger are ports {@code targets} declares ({@code TargetScans},
 * {@code TargetBacklog}), so every module that names a target can depend on it.
 *
 * <p>{@code access::security} for its routes: the markers, the principal and {@code Visibilities},
 * which every controller needs. Only its {@code web} may name them — the layer rule keeps a
 * module's service layer off every {@code web} package, {@code access}'s included.
 */
@ApplicationModule(allowedDependencies = {"access", "access::security"})
package com.asmolabs.vectispire.core.targets;

import org.springframework.modulith.ApplicationModule;
