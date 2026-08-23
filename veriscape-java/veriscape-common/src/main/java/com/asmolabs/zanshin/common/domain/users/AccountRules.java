package com.asmolabs.zanshin.common.domain.users;

import java.util.Optional;
import java.util.regex.Pattern;

/**
 * The rules that stop an administrator from locking themselves out.
 *
 * <p>Pure, because they are rules and not queries: each describes a situation the UI would
 * happily accept and nobody could come back from. <b>There is no rescue screen in Zanshin</b> —
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
            return Optional.of("This is the last active administrator: removing them would leave Zanshin "
                    + "with nobody able to administer it.");
        }
        return Optional.empty();
    }

    /** Likewise for deletion, whose consequences are the same but worse. */
    public static Optional<String> refuseDeletion(boolean isSelf, boolean isAdmin, int remainingActiveAdmins) {
        if (isSelf) {
            return Optional.of("You cannot delete your own account.");
        }
        if (isAdmin && remainingActiveAdmins == 0) {
            return Optional.of("This is the last active administrator: deleting them would leave Zanshin "
                    + "with nobody able to administer it.");
        }
        return Optional.empty();
    }
}
