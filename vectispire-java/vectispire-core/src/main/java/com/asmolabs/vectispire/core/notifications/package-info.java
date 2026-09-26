/**
 * What a scan's delta says, and the channels that say it.
 *
 * <p><b>What it may use is declared here and verified by Spring Modulith</b> ({@code
 * ModularityTest}, decision 0030): a dependency on a module, or on a named interface ({@code
 * module::name}), missing from this list fails the build, and so does a line nothing uses. A domain
 * does not list the foundation, which is shared. Adding a line is a decision for the review that
 * needs it, with its reason written beside it — not the edit that turns the build green.
 *
 * <p>{@code access} since access became a module: a scan's delta is routed to the teams granted its
 * target that have a channel, through {@code TeamChannels}. {@code issues}: the delta is the
 * backlog's, announced through {@code ScanDelta.Sink}, a port of {@code issues} (not {@code
 * scanning} since step 5). {@code targets}: a message names its target.
 *
 * <p>{@code access::security} for its routes: the markers, the principal and {@code Visibilities},
 * which every controller needs. Only its {@code web} may name them — the layer rule keeps a
 * module's service layer off every {@code web} package, {@code access}'s included.
 */
@ApplicationModule(allowedDependencies = {"access", "access::security", "issues", "targets"})
package com.asmolabs.vectispire.core.notifications;

import org.springframework.modulith.ApplicationModule;
