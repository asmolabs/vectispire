package com.asmolabs.vectispire.common.domain.users;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * The vocabulary of roles.
 *
 * <p>In the domain and not on the entity: it is a business rule, not a column. The roles would
 * still exist if Vectispire changed database.
 *
 * <p>{@link #isAdministrative()} travels with the constant rather than living in a second
 * {@code ADMIN_ROLES} list. Two lists over one set can disagree, and the disagreement here
 * grants or withholds administration.
 */
public enum Role {
    SUPERUSER(true, true, true, true),
    ADMIN(true, true, true, true),
    CISO(false, true, true, true),
    SECURITY_CHAMPION(false, false, true, false),
    AUDITOR(false, true, false, false),
    USER(false, false, false, false);

    private final boolean administrative;
    private final boolean globalSecurityScope;
    private final boolean canApproveTriage;
    private final boolean canWriteGovernance;

    Role(
            boolean administrative,
            boolean globalSecurityScope,
            boolean canApproveTriage,
            boolean canWriteGovernance) {
        this.administrative = administrative;
        this.globalSecurityScope = globalSecurityScope;
        this.canApproveTriage = canApproveTriage;
        this.canWriteGovernance = canWriteGovernance;
    }

    public boolean isAdministrative() {
        return administrative;
    }

    /**
     * Sees the whole estate without being assigned to any of it — <b>and may read its governance</b>.
     *
     * <p>The two travel together on purpose. Reading the audit log, the compliance evidence or the
     * gate policy tells you the security posture of every target there is; granting that to an
     * account whose visibility is a handful of repositories would be a way around the scope, not a
     * lesser privilege than it.
     */
    public boolean hasGlobalSecurityScope() {
        return globalSecurityScope;
    }

    /**
     * May <b>change</b> what governance says — the gate policy, the rule sets, the SIEM
     * destination, the licence policy.
     *
     * <p><b>Separated from reading it because {@link #AUDITOR} exists.</b> Until this flag, the two
     * were one privilege and the marker on those routes sat at class level, so somebody who had to
     * inspect the posture was necessarily somebody who could rewrite it. Whoever is asked to check
     * the work should not be able to change it first.
     */
    public boolean canWriteGovernance() {
        return canWriteGovernance;
    }

    public boolean canApproveTriage() {
        return canApproveTriage;
    }

    /**
     * Parses a stored or submitted role. <b>Case-sensitive</b>, unlike most parsing here: a
     * role is written by an administrator into a form with a fixed set of choices, and
     * accepting {@code admin} for {@code ADMIN} would mean accepting whatever else arrives in
     * that field.
     */
    public static Optional<Role> of(String value) {
        return value == null
                ? Optional.empty()
                : Arrays.stream(values()).filter(role -> role.name().equals(value)).findFirst();
    }

    /**
     * The roles that count as administrative.
     *
     * <p>Derived from the flag each role carries rather than listed again: two lists of
     * administrators disagree the day somebody adds a role to one of them, and the half that
     * gets forgotten is always the one used by a check.
     */
    public static List<Role> administrative() {
        return Arrays.stream(values()).filter(Role::isAdministrative).toList();
    }
}
