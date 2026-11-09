/**
 * The shell: the settings screen, which composes the credentials and checks of {@code ai}, {@code
 * tickets}, {@code notifications} and {@code access}; the audit-log and crypto routes the
 * foundation may not keep (they need {@code access}'s markers, and {@code access} uses the
 * foundation); the exception handler, the SPA forwarding and the OpenAPI configuration.
 *
 * <p><b>No allowed dependencies declared, on purpose</b>: {@code platform} may use any module
 * (decision 0029), which is what an undeclared list means to Modulith. And nothing may use it,
 * which needs no rule of its own: every other module declares its list, and none names {@code
 * platform} — {@code ModularityTest} fails if a module but this one leaves its list undeclared.
 */
@ApplicationModule
package com.asmolabs.vectispire.core.platform;

import org.springframework.modulith.ApplicationModule;
