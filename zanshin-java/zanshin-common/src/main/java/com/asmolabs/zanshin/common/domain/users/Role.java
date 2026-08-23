package com.asmolabs.zanshin.common.domain.users;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * The vocabulary of roles.
 *
 * <p>In the domain and not on the entity: it is a business rule, not a column. The roles would
 * still exist if Zanshin changed database.
 *
 * <p>{@link #isAdministrative()} travels with the constant rather than living in a second
 * {@code ADMIN_ROLES} list. Two lists over one set can disagree, and the disagreement here
 * grants or withholds administration.
 */
public enum Role {
    SUPERUSER(true, true, true),
    ADMIN(true, true, true),
    CISO(false, true, true),
    SECURITY_CHAMPION(false, false, true),
    USER(false, false, false);

    private final boolean administrative;
    private final boolean globalSecurityScope;
    private final boolean canApproveTriage;

    Role(boolean administrative, boolean globalSecurityScope, boolean canApproveTriage) {
        this.administrative = administrative;
        this.globalSecurityScope = globalSecurityScope;
        this.canApproveTriage = canApproveTriage;
    }

    public boolean isAdministrative() {
        return administrative;
    }

    public boolean hasGlobalSecurityScope() {
        return globalSecurityScope;
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
