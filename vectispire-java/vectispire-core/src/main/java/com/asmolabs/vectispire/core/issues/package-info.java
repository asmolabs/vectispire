/**
 * Sync, triage, decisions, SLA, history, the exceptions register, VEX import.
 *
 * <p><b>What it may use is declared here and verified by Spring Modulith</b> ({@code
 * ModularityTest}, decision 0030): a dependency on a module, or on a named interface ({@code
 * module::name}), missing from this list fails the build, and so does a line nothing uses. A domain
 * does not list the foundation, which is shared. Adding a line is a decision for the review that
 * needs it, with its reason written beside it — not the edit that turns the build green.
 *
 * <p>{@code access}: the backlog, its history and its decisions are read within the caller's
 * visibility ({@code VisibilityService}, {@code RowVisibility}). {@code targets} since step 5: an
 * issue belongs to a target, is named through {@code TargetNaming} and answers the listings' open
 * counts through {@code TargetBacklog}, a port {@code targets} declares. {@code scanning} since
 * step 5, and in place of {@code scanning} → {@code issues}: the backlog reads scans and findings
 * for its history and its sightings through {@code ScanCatalog}, and deletes an issue's findings
 * through {@code scanning} when a target goes; a completed scan's findings reach the backlog
 * through {@code ScanIngestor.Backlog}, a port {@code scanning} declares and {@code issues}
 * implements.
 *
 * <p>{@code access::security} for its routes: the markers, the principal and {@code Visibilities},
 * which every controller needs. Only its {@code web} may name them — the layer rule keeps a
 * module's service layer off every {@code web} package, {@code access}'s included.
 */
@ApplicationModule(allowedDependencies = {"access", "access::security", "scanning", "targets"})
package com.asmolabs.vectispire.core.issues;

import org.springframework.modulith.ApplicationModule;
