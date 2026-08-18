package com.asmolabs.zanshin.core.api.security;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * This route needs an administrative role.
 *
 * <p>The expression lives here once rather than as a string on seventeen methods. A misspelled
 * role in {@code hasAnyRole} denies everybody — fail-closed, so not a hole, but a route nobody
 * can use and an afternoon spent finding out why. One definition also means the day a fourth
 * role appears, the set of administrators is changed in one place instead of found by grep.
 *
 * <p>Kept in step with {@code Role.administrative()} by {@code RouteAuthorizationTest}, which
 * compares the two: a role added to the enum and not to this expression fails there rather than
 * silently losing access it was meant to have.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
@PreAuthorize("hasAnyRole('SUPERUSER', 'ADMIN')")
public @interface RequiresAdministrator {}
