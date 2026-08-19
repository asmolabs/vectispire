package com.asmolabs.zanshin.core.api.security;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * This route is reachable without any credential, and that is intended.
 *
 * <p>It grants nothing — the filter chain already decides what is reachable. It exists so the
 * difference between "deliberately open" and "somebody forgot the guard" is written down, and
 * so {@code RouteAuthorizationTest} can tell them apart. Without it the enumeration would have
 * to accept an unannotated method as possibly-intentional, which is the same as not enumerating.
 *
 * <p>There is exactly one: the login route. Adding a second should be a review conversation.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface OpenToAnonymous {}
