package com.asmolabs.vectispire.common.domain.users;

import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;

/**
 * What one administrator can do to another account that makes the account partly theirs: create it, choose
 * its password, choose its role.
 *
 * <p>The three gestures after which, under four-eyes, the account's holder is not a second pair of eyes on
 * the administrator's requests for a while (#126, option 1): the administrator knew the password it was
 * created or reset with, or chose that it would approve. Activating, deactivating or granting targets is
 * not one of them: none gives the administrator the account, or the account its say.
 */
public enum AccountGesture {
    CREATED,
    PASSWORD_RESET,
    ROLE_CHANGED;

    /** The name stored and sent: lowercase, as every wire name here. */
    public String wireName() {
        return name().toLowerCase(Locale.ROOT);
    }

    public static Optional<AccountGesture> fromWireName(String value) {
        return Arrays.stream(values()).filter(gesture -> gesture.wireName().equals(value)).findFirst();
    }
}
