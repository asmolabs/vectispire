package com.asmolabs.zanshin.core.api.security;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * This route authenticates by API key with the {@code agent} scope, not by session.
 *
 * <p><b>Not {@code @PreAuthorize}</b>, and the reason is the failure mode it would create. An
 * expression here would answer 403 to a request whose key is wrong — which reads to an agent as
 * "your key lacks a right" when the truth is usually "your key is not being sent at all". The
 * controller checks instead, and says which of the two it is: absent, invalid, missing the
 * scope, or belonging to a disabled agent.
 *
 * <p>Forgetting the check on one route would open the scan queue to whoever knows the URL, which
 * is why {@code RouteAuthorizationTest} requires this marker <em>and</em> asserts the controller
 * refuses an anonymous call on every route that carries it.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface RequiresAgentKey {}
