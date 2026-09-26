/**
 * The queue, dispatch, ingest, the built-in worker, scheduling, scan reads, retention.
 *
 * <p><b>What it may use is declared here and verified by Spring Modulith</b> ({@code
 * ModularityTest}, decision 0030): a dependency on a module, or on a named interface ({@code
 * module::name}), missing from this list fails the build, and so does a line nothing uses. A domain
 * does not list the foundation, which is shared. Adding a line is a decision for the review that
 * needs it, with its reason written beside it — not the edit that turns the build green.
 *
 * <p>{@code access}: a scan is read within the caller's visibility, and the dispatcher hands a task
 * to the agent the principal carries ({@code AgentView}). {@code targets} since step 5: a scan is
 * of a target — the dispatcher reads its row and credentials, the scheduler its schedule — and the
 * target screens' latest scan and "scan now" are answered through {@code TargetScans}, a port
 * {@code targets} declares. What it needs of higher modules is a port it declares: {@code
 * ScanIngestor.Backlog}, {@code ScanIngestor.InventorySink}, {@code ScanRuleSets}, {@code
 * AgentClaimLock}.
 *
 * <p>{@code access::security} for its routes: the markers, the principal and {@code Visibilities},
 * which every controller needs. Only its {@code web} may name them — the layer rule keeps a
 * module's service layer off every {@code web} package, {@code access}'s included.
 */
@ApplicationModule(allowedDependencies = {"access", "access::security", "targets"})
package com.asmolabs.vectispire.core.scanning;

import org.springframework.modulith.ApplicationModule;
