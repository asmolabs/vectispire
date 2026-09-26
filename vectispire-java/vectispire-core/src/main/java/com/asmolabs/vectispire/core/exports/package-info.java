/**
 * VEX, CSAF, CycloneDX, attestation, the export documents.
 *
 * <p><b>What it may use is declared here and verified by Spring Modulith</b> ({@code
 * ModularityTest}, decision 0030): a dependency on a module, or on a named interface ({@code
 * module::name}), missing from this list fails the build, and so does a line nothing uses. A domain
 * does not list the foundation, which is shared. Adding a line is a decision for the review that
 * needs it, with its reason written beside it — not the edit that turns the build green.
 *
 * <p>{@code gate}: the attestation states the last verdict ({@code GateRegisterService}), and a
 * target's export its posture ({@code GateService}). {@code issues} (and {@code issues::queries}'
 * {@code IssueFilters}): the documents state the backlog, its decisions and deadlines, and a VEX
 * document is imported through {@code VexIngestorService}. {@code scanning} since exports became a
 * module and took its controllers: a document is made for a scan, and its route first refuses a
 * scan the caller may not see. {@code targets}: a document names its target. None of them uses
 * {@code exports}.
 *
 * <p>{@code access} for its routes only, which resolve a {@code Visibility} ({@code
 * ArchitectureTest.accessForRoutesOnly}).
 *
 * <p>{@code access::security} for its routes: the markers, the principal and {@code Visibilities},
 * which every controller needs. Only its {@code web} may name them — the layer rule keeps a
 * module's service layer off every {@code web} package, {@code access}'s included.
 */
@ApplicationModule(allowedDependencies = {
        "access", "access::security", "gate", "issues", "issues::queries", "scanning", "targets"})
package com.asmolabs.vectispire.core.exports;

import org.springframework.modulith.ApplicationModule;
