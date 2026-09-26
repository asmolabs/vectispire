/**
 * The relay: {@code OutboxService}, and the two contracts it dispatches to, {@code OutboxHandler}
 * and {@code NotificationChannel}, with {@code GoneDestinationException}.
 *
 * <p><b>What it may use is declared here and verified by Spring Modulith</b> ({@code
 * ModularityTest}, decision 0030): a dependency on a module, or on a named interface ({@code
 * module::name}), missing from this list fails the build, and so does a line nothing uses. A domain
 * does not list the foundation, which is shared. Adding a line is a decision for the review that
 * needs it, with its reason written beside it — not the edit that turns the build green.
 *
 * <p>{@code maintenance} since step 5: the relay and the purge of delivered messages are the
 * outbox's contributions to the periodic tick. {@code maintenance} uses nothing, so no cycle can
 * close.
 *
 * <p><b>Foundation, declared shared on {@code VectispireApplication}</b>: every module may use it.
 * Modulith adds the shared modules to every module's allowed dependencies, the foundation's own
 * included, so {@code verify()} alone would let one foundation module use any other: {@code
 * ModularityTest.eachModuleDeclaresExactlyWhatItUses} holds this list to the code.
 */
@ApplicationModule(allowedDependencies = {"maintenance"})
package com.asmolabs.vectispire.core.outbox;

import org.springframework.modulith.ApplicationModule;
