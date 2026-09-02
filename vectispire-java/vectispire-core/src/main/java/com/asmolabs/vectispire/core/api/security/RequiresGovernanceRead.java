package com.asmolabs.vectispire.core.api.security;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * This route <b>reads</b> the estate's security governance: the audit log, the compliance
 * evidence, the gate policy, the rule sets, the SIEM destination.
 *
 * <p><b>Why it is not {@link RequiresSecurityLead}.</b> It was, and at class level, so the two were
 * the same privilege: the only account that could inspect the posture was one that could rewrite
 * it. An auditor — internal, external, or a manager asked to confirm the state of things — had a
 * choice between seeing almost nothing and being able to change almost everything. Whoever is
 * asked to check the work should not be able to change it first.
 *
 * <p>The set is exactly {@code Role.hasGlobalSecurityScope()}, and
 * {@code RouteAuthorizationTest} holds the two together. That pairing is the definition, not a
 * coincidence: what these routes disclose is the posture of every target there is, which is the
 * same disclosure as seeing every target without being assigned one.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
@PreAuthorize("hasAnyRole('SUPERUSER', 'ADMIN', 'CISO', 'AUDITOR')")
public @interface RequiresGovernanceRead {}
