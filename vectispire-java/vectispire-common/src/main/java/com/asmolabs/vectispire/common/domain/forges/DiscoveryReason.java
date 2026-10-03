package com.asmolabs.vectispire.common.domain.forges;

import com.fasterxml.jackson.annotation.JsonValue;
import java.util.Arrays;
import java.util.Optional;

/**
 * Why a discovery ended short of {@code completed} (decision 0037 §3): a closed word a screen reads without
 * parsing a sentence, and the state it belongs to — a reason is never paired with the other one.
 *
 * <p>The partial ones are bounds: what was listed is kept and compared, and nothing is marked gone. The failed
 * ones say what to fix, and whose: the token, the address, the forge, or the connection's own trust.
 */
public enum DiscoveryReason {
    /** Thirty minutes went by — or the bound configured instead — before the listing ended. */
    TIME_BOUND("time_bound", DiscoveryState.PARTIAL),
    /** Twenty thousand repositories — or the bound configured instead — were read; discover per group past it. */
    REPOSITORY_BOUND("repository_bound", DiscoveryState.PARTIAL),
    /** A rate limit asked for a longer wait than a discovery spends inside its run; the run says when it lifts. */
    RATE_LIMITED("rate_limited", DiscoveryState.PARTIAL),

    /** The forge answered 401: the token is wrong, expired or revoked. */
    TOKEN_REJECTED("token_rejected", DiscoveryState.FAILED),
    /** The outbound guard refused the address — it resolves where this connection may not go, now. */
    DESTINATION_BLOCKED("destination_blocked", DiscoveryState.FAILED),
    /** A next page named another scheme, host or port: nothing was sent there, and the run stopped. */
    CROSS_ORIGIN_PAGE("cross_origin_page", DiscoveryState.FAILED),
    /** The forge did not answer — timeouts, resets, 5xx — three retries over, or answered a document unreadable. */
    FORGE_UNAVAILABLE("forge_unavailable", DiscoveryState.FAILED),
    /** The forge refused a listing the token needs (a 403 or a 404 where an answer was due). */
    FORGE_REFUSED("forge_refused", DiscoveryState.FAILED),
    /** The connection cannot be used as stored: its token no longer decrypts, or its pinned CA has expired. */
    CONNECTION_UNUSABLE("connection_unusable", DiscoveryState.FAILED),
    /** No adapter lists this forge's repositories in this version. */
    UNSUPPORTED("unsupported", DiscoveryState.FAILED),
    /** The instances that took the run stopped answering, three times: it is not taken a fourth. */
    EXECUTOR_LOST("executor_lost", DiscoveryState.FAILED),
    /** Something this version did not foresee; the log carries the rest. */
    INTERNAL_ERROR("internal_error", DiscoveryState.FAILED);

    private final String wireName;
    private final DiscoveryState state;

    DiscoveryReason(String wireName, DiscoveryState state) {
        this.wireName = wireName;
        this.state = state;
    }

    @JsonValue
    public String wireName() {
        return wireName;
    }

    /** {@link DiscoveryState#PARTIAL} or {@link DiscoveryState#FAILED}. */
    public DiscoveryState state() {
        return state;
    }

    /** A stored value read back; absent for a run that has none. */
    public static Optional<DiscoveryReason> ofStored(String stored) {
        if (stored == null) {
            return Optional.empty();
        }
        return Optional.of(Arrays.stream(values()).filter(reason -> reason.wireName.equals(stored)).findFirst()
                .orElseThrow(() -> new IllegalStateException("Unknown discovery reason \"" + stored + "\".")));
    }
}
