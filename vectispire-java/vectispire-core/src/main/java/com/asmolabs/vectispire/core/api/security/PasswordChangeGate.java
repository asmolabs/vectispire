package com.asmolabs.vectispire.core.api.security;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a route as reachable by an account that still has to change its password.
 *
 * <p>Reserved for what lets somebody <em>out</em> of that state: reading one's own profile,
 * changing the password, signing out. Every other route is refused while the flag is set.
 *
 * <p><b>An allow-list, not a deny-list</b>, and that asymmetry is the whole point: a route
 * added tomorrow is refused by default, where a deny-list would let it through and nobody
 * would notice until the flag stopped meaning anything.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface PasswordChangeGate {

    /** Whether this route stays reachable while a password change is pending. */
    boolean allowsPending() default true;
}
