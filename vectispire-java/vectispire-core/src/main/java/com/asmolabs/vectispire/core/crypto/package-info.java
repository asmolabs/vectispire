/**
 * Encryption at rest, the key's sources, Vault, the document signing key.
 *
 * <p><b>What it may use is declared here and verified by Spring Modulith</b> ({@code
 * ModularityTest}, decision 0030): a dependency on a module, or on a named interface ({@code
 * module::name}), missing from this list fails the build, and so does a line nothing uses. A domain
 * does not list the foundation, which is shared. Adding a line is a decision for the review that
 * needs it, with its reason written beside it — not the edit that turns the build green.
 *
 * <p>{@code outbound}: Vault is reached through the guard like any other destination. {@code
 * settings}: the signing key is kept in a {@code t_setting} row, read and written through {@code
 * SettingsService} since the foundation became modules (decision 0028). Neither uses {@code
 * crypto}, so no cycle can close.
 *
 * <p><b>Foundation, declared shared on {@code VectispireApplication}</b>: every module may use it.
 * Modulith adds the shared modules to every module's allowed dependencies, the foundation's own
 * included, so {@code verify()} alone would let one foundation module use any other: {@code
 * ModularityTest.eachModuleDeclaresExactlyWhatItUses} holds this list to the code.
 */
@ApplicationModule(allowedDependencies = {"outbound", "settings"})
package com.asmolabs.vectispire.core.crypto;

import org.springframework.modulith.ApplicationModule;
