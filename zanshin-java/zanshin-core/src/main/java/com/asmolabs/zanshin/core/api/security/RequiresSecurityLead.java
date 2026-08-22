package com.asmolabs.zanshin.core.api.security;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * This route requires an administrative or security governance role (SUPERUSER, ADMIN, or CISO).
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
@PreAuthorize("hasAnyRole('SUPERUSER', 'ADMIN', 'CISO')")
public @interface RequiresSecurityLead {}
