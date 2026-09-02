package com.asmolabs.vectispire.core.api.security;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * This route <b>changes</b> the estate's security governance — the gate policy, the rule sets, the
 * SIEM destination, the licence policy, the platform settings.
 *
 * <p><b>Reading the same things is {@link RequiresGovernanceRead}</b>, which is a wider set. Until
 * that marker existed the two were one privilege, so an account that had to inspect the posture
 * was necessarily one that could rewrite it.
 *
 * <p>The set is exactly {@code Role.canWriteGovernance()}, and {@code RouteAuthorizationTest}
 * holds the two together.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
@PreAuthorize("hasAnyRole('SUPERUSER', 'ADMIN', 'CISO')")
public @interface RequiresSecurityLead {}
