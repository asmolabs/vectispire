/**
 * Rule sets, the upstream catalogue, rule coverage.
 *
 * <p><b>What it may use is declared here and verified by Spring Modulith</b> ({@code
 * ModularityTest}, decision 0030): a dependency on a module, or on a named interface ({@code
 * module::name}), missing from this list fails the build, and so does a line nothing uses. A domain
 * does not list the foundation, which is shared. Adding a line is a decision for the review that
 * needs it, with its reason written beside it — not the edit that turns the build green.
 *
 * <p>{@code inventory} since inventory became a module: rule coverage compares the rule sets with
 * the package URLs the components inventory holds ({@code InventoryQueryService}). {@code issues}
 * since step 5: a rule set's impact on the open SAST issues is asked of {@code IssueCatalog}.
 * {@code scanning} since step 5, and in place of {@code scanning} → {@code rules}: a scan asks
 * which rule set is active and fetches its files through {@code ScanRuleSets}, a port {@code
 * scanning} declares and {@code rules} implements — called the other way, {@code scanning} → {@code
 * rules} → {@code inventory} → {@code scanning} would be a cycle.
 *
 * <p>Not {@code access}: its routes use the security vocabulary and nothing else.
 *
 * <p>{@code access::security} for its routes: the markers, the principal and {@code Visibilities},
 * which every controller needs. Only its {@code web} may name them — the layer rule keeps a
 * module's service layer off every {@code web} package, {@code access}'s included.
 */
@ApplicationModule(allowedDependencies = {"access::security", "inventory", "issues", "scanning"})
package com.asmolabs.vectispire.core.rules;

import org.springframework.modulith.ApplicationModule;
