package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.common.domain.errors.ConflictException;
import com.asmolabs.vectispire.common.domain.users.AccountGesture;
import java.util.Map;

/**
 * An approval refused because its requester administered the approver's account recently: 409, with the type
 * {@code urn:vectispire:problem:approver-not-independent}, the code {@code approver-not-independent} and the
 * members {@code gesture} and {@code windowDays}.
 *
 * <p>A 409 like the other four-eyes refusals: the request is well formed, and the same approval by somebody
 * else, or by the same account once the window has passed, succeeds. The sentence names what the requester
 * did and to whom — the approver's own account, which the approver may know about — and nothing else.
 */
public final class ApproverNotIndependentException extends ConflictException {

    /** The token the problem's {@code type} ends with, published in the routes' descriptions. */
    public static final String CAUSE = "approver-not-independent";

    /** The requester administered the approver. */
    static ApproverNotIndependentException ofApprover(String requester, AccountGesture gesture, int windowDays) {
        return new ApproverNotIndependentException(requester + " " + done(gesture, "your account") + " within the last "
                + windowDays + " days, so you cannot approve what " + requester + " asked for: four-eyes needs an "
                + "approver " + requester + " did not administer. Somebody else has to approve it.", gesture, windowDays);
    }

    /** The other way round: the approver administered the requester, who may be the approver's own second name. */
    static ApproverNotIndependentException ofRequester(String requester, AccountGesture gesture, int windowDays) {
        return new ApproverNotIndependentException("You " + done(gesture, requester + "'s account") + " within the last "
                + windowDays + " days, so you cannot approve " + requester + "'s account requests: an administrator you "
                + "made could be your own second name. Somebody else has to approve it.", gesture, windowDays);
    }

    private ApproverNotIndependentException(String sentence, AccountGesture gesture, int windowDays) {
        super(sentence, CAUSE, Map.of("gesture", gesture.wireName(), "windowDays", windowDays));
    }

    static String done(AccountGesture gesture, String account) {
        return switch (gesture) {
            case CREATED -> "created " + account;
            case PASSWORD_RESET -> "reset the password of " + account;
            case ROLE_CHANGED -> "changed the role of " + account;
        };
    }
}
