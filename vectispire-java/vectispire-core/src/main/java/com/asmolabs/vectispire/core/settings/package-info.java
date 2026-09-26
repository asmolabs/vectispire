/**
 * The deployment's configuration: {@code SettingsService}, the first-install defaults, and what
 * Vectispire says about itself ({@code ProductVersion}, {@code ExportProperties}, {@code
 * BrandingProperties}).
 *
 * <p><b>What it may use is declared here and verified by Spring Modulith</b> ({@code
 * ModularityTest}, decision 0030): a dependency on a module, or on a named interface ({@code
 * module::name}), missing from this list fails the build, and so does a line nothing uses. A domain
 * does not list the foundation, which is shared. Adding a line is a decision for the review that
 * needs it, with its reason written beside it — not the edit that turns the build green.
 *
 * <p>It uses nothing: every other module reads its settings, so a dependency of its own could only
 * close a cycle.
 *
 * <p><b>Foundation, declared shared on {@code VectispireApplication}</b>: every module may use it.
 * Modulith adds the shared modules to every module's allowed dependencies, the foundation's own
 * included, so {@code verify()} alone would let one foundation module use any other: {@code
 * ModularityTest.eachModuleDeclaresExactlyWhatItUses} holds this list to the code.
 */
@ApplicationModule(allowedDependencies = {})
package com.asmolabs.vectispire.core.settings;

import org.springframework.modulith.ApplicationModule;
