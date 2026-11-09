package com.asmolabs.vectispire.common.domain.forges;

import com.fasterxml.jackson.annotation.JsonValue;
import java.util.Arrays;

/**
 * Where one discovery of a forge connection stands (decision 0037 §3). Exactly one at a time.
 *
 * <ul>
 *   <li>{@link #PENDING} — requested, waiting for a control-plane instance to claim it; also a run whose
 *       instance stopped answering and that is waiting to be taken again — a restart resumes a discovery
 *       rather than losing it;
 *   <li>{@link #RUNNING} — claimed under a lease the run renews as it goes;
 *   <li>{@link #COMPLETED} — every namespace and every repository the token can list was read. <b>Only this
 *       state marks a repository gone</b>;
 *   <li>{@link #PARTIAL} — a bound ended it — thirty minutes, twenty thousand repositories, a rate limit asking
 *       for longer than a minute: what was read is kept, and nothing is inferred from what was not;
 *   <li>{@link #FAILED} — nothing usable came of it: the token was rejected, the address refused, the forge
 *       did not answer, or a next page pointed elsewhere.
 * </ul>
 */
public enum DiscoveryState {
    PENDING("pending"),
    RUNNING("running"),
    COMPLETED("completed"),
    PARTIAL("partial"),
    FAILED("failed");

    private final String wireName;

    DiscoveryState(String wireName) {
        this.wireName = wireName;
    }

    /** The value the column stores and the API carries. */
    @JsonValue
    public String wireName() {
        return wireName;
    }

    /** Ended: nothing moves it any more, and the connection may be discovered again. */
    public boolean ended() {
        return this == COMPLETED || this == PARTIAL || this == FAILED;
    }

    /** A stored value read back; a value this version does not know is a fault of the row, not a state. */
    public static DiscoveryState ofStored(String stored) {
        return Arrays.stream(values()).filter(state -> state.wireName.equals(stored)).findFirst()
                .orElseThrow(() -> new IllegalStateException("Unknown discovery state \"" + stored + "\"."));
    }
}
