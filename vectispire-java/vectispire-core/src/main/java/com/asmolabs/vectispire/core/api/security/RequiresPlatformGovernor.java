package com.asmolabs.vectispire.core.api.security;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * This route changes a rule everyone else plays by, rather than doing work under one.
 *
 * <p>The set is exactly {@code Role.governsPlatform()} — {@code SUPERUSER} alone — and
 * {@code RouteAuthorizationTest} holds the two together. Reserved for the two settings that decide
 * who sees which targets and whether writing off a vulnerability needs a second person; every other
 * setting stays with {@link RequiresSecurityLead}, because an administrator changing a scanner
 * threshold is ordinary work.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
@PreAuthorize("hasAnyRole('SUPERUSER')")
public @interface RequiresPlatformGovernor {}
