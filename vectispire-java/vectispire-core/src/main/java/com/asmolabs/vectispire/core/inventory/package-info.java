/**
 * What targets are made of: components, SBOM diff, blast radius, licences, API contracts.
 *
 * <p><b>What it may use is declared here and verified by Spring Modulith</b> ({@code
 * ModularityTest}, decision 0030): a dependency on a module, or on a named interface ({@code
 * module::name}), missing from this list fails the build, and so does a line nothing uses. A domain
 * does not list the foundation, which is shared. Adding a line is a decision for the review that
 * needs it, with its reason written beside it — not the edit that turns the build green.
 *
 * <p>{@code scanning} since step 5, and in place of {@code scanning} → {@code inventory}: the
 * inventory reads scans and findings through {@code ScanCatalog} (licences, SBOM diff, blast
 * radius, the purge's selection), while a scan's components reach it through {@code
 * ScanIngestor.InventorySink}, a port {@code scanning} declares and {@code inventory} implements;
 * {@code scanning::queries} for {@code PackageImpact}. {@code targets}: a component is named by the
 * target it was seen in.
 *
 * <p>{@code access} for its routes only, which resolve a {@code Visibility} through {@code
 * VisibilityService}: its service layer does not use {@code access}, which {@code
 * ArchitectureTest.accessForRoutesOnly} holds, since a module's allowed dependencies are one list
 * for the whole module.
 *
 * <p>{@code access::security} for its routes: the markers, the principal and {@code Visibilities},
 * which every controller needs. Only its {@code web} may name them — the layer rule keeps a
 * module's service layer off every {@code web} package, {@code access}'s included.
 */
@ApplicationModule(allowedDependencies = {
        "access", "access::security", "scanning", "scanning::queries", "targets"})
package com.asmolabs.vectispire.core.inventory;

import org.springframework.modulith.ApplicationModule;
