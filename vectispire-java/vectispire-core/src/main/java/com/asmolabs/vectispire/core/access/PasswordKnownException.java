package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.common.domain.errors.ConflictException;
import com.asmolabs.vectispire.common.domain.users.AccountGesture;
import java.util.Map;

/**
 * A raise to a role that approves, refused because an administrator behind it — its requester or its
 * approver — created the account or reset its password recently: 409, with the type {@code
 * urn:vectispire:problem:password-known-to-administrator}, the code {@code password-known-to-administrator}
 * and the members {@code gesture} and {@code windowDays}.
 *
 * <p><b>Lower, reset, raise.</b> Lowering a role and resetting the password of an account that approves
 * nothing both apply at once; the raise that follows was filed as "restore this account's role", and the
 * approver had no way to see that the requester had just typed its password. The raise is refused instead,
 * and filed by somebody else, or after the window.
 */
public final class PasswordKnownException extends ConflictException {

    /** The token the problem's {@code type} ends with, published in the routes' descriptions. */
    public static final String CAUSE = "password-known-to-administrator";

    PasswordKnownException(String administrator, String account, AccountGesture gesture, int windowDays) {
        super(administrator + " " + ApproverNotIndependentException.done(gesture, account) + " within the last "
                        + windowDays + " days and may know its password, so " + account + " cannot be given a role that "
                        + "approves through a request " + administrator + " filed or approves. Another administrator has "
                        + "to file and approve it, or it waits until the window has passed.",
                CAUSE,
                Map.of("gesture", gesture.wireName(), "windowDays", windowDays));
    }
}
