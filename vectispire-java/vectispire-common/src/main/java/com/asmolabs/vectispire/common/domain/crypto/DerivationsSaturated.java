package com.asmolabs.vectispire.common.domain.crypto;

import java.time.Duration;

/**
 * Every password derivation permit is taken and none came free in time — see {@link DerivationGate}.
 *
 * <p>Transient by construction, and answered {@code 503} with {@code Retry-After}. It says nothing about
 * the password or the account: the permit is asked for before anything is compared, for a name nobody
 * holds exactly as for an account's.
 */
public final class DerivationsSaturated extends RuntimeException {

    private final transient Duration retryAfter;

    public DerivationsSaturated(Duration retryAfter) {
        super("Too many passwords are being verified at once. Try again in a few seconds.");
        this.retryAfter = retryAfter;
    }

    public Duration retryAfter() {
        return retryAfter;
    }
}
