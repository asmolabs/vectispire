package com.asmolabs.vectispire.core.access;

import java.time.Duration;

/** {@link AuthService#PAST_BUDGET_DEADLINE}, which is package-private, for the HTTP suite. */
public final class AuthServiceDeadline {

    private AuthServiceDeadline() {}

    public static Duration value() {
        return AuthService.PAST_BUDGET_DEADLINE;
    }
}
