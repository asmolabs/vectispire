/**
 * KEV/EPSS feeds, enrichment, end of life.
 *
 * <p><b>What it may use is declared here and verified by Spring Modulith</b> ({@code
 * ModularityTest}, decision 0030): a dependency on a module, or on a named interface ({@code
 * module::name}), missing from this list fails the build, and so does a line nothing uses. A domain
 * does not list the foundation, which is shared. Adding a line is a decision for the review that
 * needs it, with its reason written beside it — not the edit that turns the build green.
 *
 * <p>{@code issues}: the feed re-evaluates the backlog's exploitation and the EPSS ranking reads
 * the open issues, through {@code IssueCatalog} and {@code issues::queries}. {@code scanning}:
 * enrichment and end of life are {@code ScanIngestor.Enricher} and {@code
 * ScanIngestor.EndOfLifeSource}, ports {@code scanning} declares and this module implements. {@code
 * siem}: a critical finding the KEV catalogue lists is a security event ({@code
 * CRITICAL_KEV_DETECTED}). {@code targets}: the ranking names each issue's target.
 *
 * <p>{@code access} for its routes only, which resolve a {@code Visibility}: its service layer does
 * not use {@code access} ({@code ArchitectureTest.accessForRoutesOnly}).
 *
 * <p>{@code access::security} for its routes: the markers, the principal and {@code Visibilities},
 * which every controller needs. Only its {@code web} may name them — the layer rule keeps a
 * module's service layer off every {@code web} package, {@code access}'s included.
 */
@ApplicationModule(allowedDependencies = {
        "access", "access::security", "issues", "issues::queries", "scanning", "siem", "targets"})
package com.asmolabs.vectispire.core.threatintel;

import org.springframework.modulith.ApplicationModule;
