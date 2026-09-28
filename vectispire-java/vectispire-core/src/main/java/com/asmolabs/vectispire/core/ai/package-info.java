/**
 * The model review and the advisor.
 *
 * <p><b>What it may use is declared here and verified by Spring Modulith</b> ({@code
 * ModularityTest}, decision 0030): a dependency on a module, or on a named interface ({@code
 * module::name}), missing from this list fails the build, and so does a line nothing uses. A domain
 * does not list the foundation, which is shared. Adding a line is a decision for the review that
 * needs it, with its reason written beside it — not the edit that turns the build green.
 *
 * <p>{@code access}: an issue is read within the caller's visibility ({@code VisibilityService},
 * {@code RowVisibility}). {@code issues}: the advisor explains an issue, asked of {@code
 * IssueCatalog} since step 5.
 *
 * <p>{@code threatintel}: the advice states a vulnerability's KEV listing and EPSS score as the
 * stored feeds hold them, unknown included ({@code ThreatIntelFeedService.exploitationOf}). The
 * fallback for a CVE the estate does not carry made both up — two identifiers typed in as
 * exploited, and an EPSS of 0.75 for every other — because it had nothing to ask.
 *
 * <p>{@code access::security} for its routes: the markers, the principal and {@code Visibilities},
 * which every controller needs. Only its {@code web} may name them — the layer rule keeps a
 * module's service layer off every {@code web} package, {@code access}'s included.
 */
@ApplicationModule(allowedDependencies = {"access", "access::security", "issues", "threatintel"})
package com.asmolabs.vectispire.core.ai;

import org.springframework.modulith.ApplicationModule;
