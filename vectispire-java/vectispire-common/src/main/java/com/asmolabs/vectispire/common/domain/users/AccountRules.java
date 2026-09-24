package com.asmolabs.vectispire.common.domain.users;

import java.util.Optional;
import java.util.regex.Pattern;

/**
 * The rules that stop an administrator from locking themselves out.
 *
 * <p>Pure, because they are rules and not queries: each describes a situation the UI would
 * happily accept and nobody could come back from. <b>There is no rescue screen in Vectispire</b> —
 * with no active administrator left, recovery means a database session.
 *
 * <p>Refused at the account level rather than the screen's: three tabs open on two accounts
 * would otherwise be enough to empty the administrator list.
 */
public final class AccountRules {

    private AccountRules() {}

    public static final int MINIMUM_PASSWORD_LENGTH = 12;

    private static final Pattern USERNAME = Pattern.compile("^[A-Za-z0-9._-]{2,64}$");

    /** Empty if the name is acceptable, otherwise the message to show. */
    public static Optional<String> validateUsername(String username) {
        if (username == null || username.isEmpty()) {
            return Optional.of("A username is required.");
        }
        if (!USERNAME.matcher(username).matches()) {
            return Optional.of("Invalid username: 2 to 64 characters, letters, digits, \". _ -\".");
        }
        return Optional.empty();
    }

    /**
     * A minimum length, and nothing else.
     *
     * <p>No composition rule. Character-class requirements produce {@code Password1!} and
     * encourage reuse; length is the only constraint whose effect on entropy is real.
     *
     * <p><b>The 72-byte ceiling is gone with bcrypt.</b> It existed because bcrypt silently
     * ignores everything past that, so accepting a longer password would have let someone
     * believe a 90-character passphrase protected them while a third of it was never hashed.
     * Argon2id has no such limit, and refusing long passwords was never the goal.
     */
    public static Optional<String> validatePassword(String password) {
        if (password == null || password.isEmpty()) {
            return Optional.of("A password is required.");
        }
        if (password.length() < MINIMUM_PASSWORD_LENGTH) {
            return Optional.of("The password must be at least " + MINIMUM_PASSWORD_LENGTH + " characters.");
        }
        return Optional.empty();
    }

    /**
     * @param remainingActiveAdmins active administrators <b>other than this account</b>
     */
    public record Change(
            boolean isSelf, boolean wasAdmin, boolean willBeAdmin, boolean willBeActive, int remainingActiveAdmins) {}

    /** Empty if the change is allowed, otherwise why it is refused. */
    public static Optional<String> refuseSelfLockout(Change change) {
        if (change.isSelf() && !change.willBeActive()) {
            return Optional.of("You cannot deactivate your own account.");
        }
        if (change.isSelf() && change.wasAdmin() && !change.willBeAdmin()) {
            return Optional.of("You cannot remove your own administrator role.");
        }

        boolean losesAdmin = change.wasAdmin() && (!change.willBeAdmin() || !change.willBeActive());
        if (losesAdmin && change.remainingActiveAdmins() == 0) {
            return Optional.of("This is the last active administrator: removing them would leave Vectispire "
                    + "with nobody able to administer it.");
        }
        return Optional.empty();
    }

    /**
     * Only a platform governor may grant, remove or administer the platform governor role.
     *
     * <p><b>The separation of duties rests on this.</b> The governor is the one role that can lift
     * the rules — four-eyes, visibility — and the one that cannot act under them. An administrator
     * could make itself governor, lift four-eyes, turn itself back into an administrator and settle
     * issues alone; or create a second governor account, or reset an existing governor's password
     * and sign in as it. Each was one request, and the two roles were one in all but name.
     *
     * @param acting the acting account's role, empty when the caller is not an account
     * @param current the target's role before the change, empty for an account being created
     * @param next the target's role after the change, empty when the change does not touch it
     * @return why it is refused, or empty
     */
    public static Optional<String> refuseGovernorAdministration(
            Optional<Role> acting, Optional<Role> current, Optional<Role> next) {
        boolean touchesGovernor = current.map(Role::governsPlatform).orElse(false)
                || next.map(Role::governsPlatform).orElse(false);
        if (touchesGovernor && !acting.map(Role::governsPlatform).orElse(false)) {
            return Optional.of("Only a platform governor can grant, remove or administer the platform governor "
                    + "role: it is the role that lifts the rules the others act under.");
        }
        return Optional.empty();
    }

    /**
     * Nobody changes their own role, up or down.
     *
     * <p>{@link #refuseSelfLockout} already refuses the way down for an administrator; the way up is
     * the other half, and it is the one an escalation takes. Another account has to make the change.
     */
    public static Optional<String> refuseOwnRoleChange(boolean isSelf, String currentRole, String nextRole) {
        if (isSelf && nextRole != null && !nextRole.equalsIgnoreCase(currentRole)) {
            return Optional.of("You cannot change your own role: another administrator has to.");
        }
        return Optional.empty();
    }

    /** Likewise for deletion, whose consequences are the same but worse. */
    public static Optional<String> refuseDeletion(boolean isSelf, boolean isAdmin, int remainingActiveAdmins) {
        if (isSelf) {
            return Optional.of("You cannot delete your own account.");
        }
        if (isAdmin && remainingActiveAdmins == 0) {
            return Optional.of("This is the last active administrator: deleting them would leave Vectispire "
                    + "with nobody able to administer it.");
        }
        return Optional.empty();
    }
}
