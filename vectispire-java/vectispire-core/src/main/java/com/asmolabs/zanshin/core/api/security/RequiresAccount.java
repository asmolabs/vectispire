package com.asmolabs.zanshin.core.api.security;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * This route needs a signed-in account, of any role.
 *
 * <p><b>Redundant with the filter chain, deliberately.</b> {@code SecurityConfiguration} already
 * ends in {@code anyRequest().authenticated()}, so this changes nothing today. It changes
 * something the day somebody adds a {@code permitAll} pattern to open one route and opens six
 * — the chain is a list of patterns read in order, and a pattern is easy to write wider than
 * intended. The rule stated on the method cannot be widened from a distance.
 *
 * <p>The other half of the argument is that it makes the absence visible: {@code
 * RouteAuthorizationTest} walks every handler and fails on one that carries neither this nor
 * {@link RequiresAdministrator}, so "we forgot to guard the new endpoint" stops being something
 * a reviewer has to notice.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
@PreAuthorize("isAuthenticated()")
public @interface RequiresAccount {}
