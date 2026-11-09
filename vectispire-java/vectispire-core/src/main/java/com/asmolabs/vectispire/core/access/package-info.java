/**
 * Accounts, teams, visibility and the row guard, sessions, sign-in flows, second factors, OIDC,
 * SCIM, API keys, bootstrap — and, in {@code web.security}, the vocabulary every module's routes
 * use.
 *
 * <p><b>What it may use is declared here and verified by Spring Modulith</b> ({@code
 * ModularityTest}, decision 0030): a dependency on a module, or on a named interface ({@code
 * module::name}), missing from this list fails the build, and so does a line nothing uses. A domain
 * does not list the foundation, which is shared. Adding a line is a decision for the review that
 * needs it, with its reason written beside it — not the edit that turns the build green.
 *
 * <p>It uses nothing above the foundation, which is why every route of every module may use it
 * without a cycle being possible. What it needs from above is declared here as a port and
 * implemented there: {@code GrantableTargets} by {@code targets}, {@code AgentDirectory} by {@code
 * agents}.
 */
@ApplicationModule(allowedDependencies = {})
package com.asmolabs.vectispire.core.access;

import org.springframework.modulith.ApplicationModule;
