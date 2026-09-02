package com.asmolabs.vectispire.core.api.security;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * This route <b>does something</b>: it records a decision, writes into another system, or sends
 * data outward. Every signed-in account may call it except a read-only one.
 *
 * <p><b>Why it is not {@link RequiresAccount}.</b> It was, and that made {@code AUDITOR} a lie.
 * The role is documented — in its own javadoc, in the security view, in the user guide — as seeing
 * the whole estate and changing nothing anywhere. Meanwhile six routes behind the plain
 * signed-in marker let it settle an issue, open a ticket in a customer's GitLab, and put a
 * target's finding list on a wire towards a model host.
 *
 * <p>The set is exactly {@code Role.canCauseEffects()}, and {@code RouteAuthorizationTest} holds
 * the two together. It is deliberately wide: an ordinary user belongs in it, because triaging is
 * ordinary work. Only the account whose whole purpose is to look is outside.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
@PreAuthorize("hasAnyRole('SUPERUSER', 'ADMIN', 'CISO', 'SECURITY_CHAMPION', 'USER')")
public @interface RequiresWriteAccount {}
