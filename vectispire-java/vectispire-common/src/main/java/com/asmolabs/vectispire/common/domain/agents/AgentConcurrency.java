package com.asmolabs.vectispire.common.domain.agents;

import java.util.Optional;
import java.util.OptionalInt;

/**
 * How many scans one agent runs at once: the bound, and its reading.
 *
 * <p><b>In the common module because both ends apply it.</b> The control plane refuses a claim
 * past the limit, the agent stops polling at it; two copies of the bound would be two answers to
 * "may this agent take another scan", and the one that answers more generously wins.
 *
 * <p><b>Sixteen is a ceiling on what one machine does well, not on what it accepts.</b> A scan
 * runs up to five scanner containers one after the other, each capped at 2 GB and most of the
 * host's cores, plus a clone and a vulnerability database of about 2 GB on disk. Past a handful
 * the scans compete for the same cores and all of them slow down; past sixteen they time out
 * together, which is worse than queueing. More capacity than that is another agent.
 */
public final class AgentConcurrency {

    private AgentConcurrency() {}

    public static final int MIN = 1;

    public static final int MAX = 16;

    /** What an agent declared without saying runs: the behaviour every agent had before the setting. */
    public static final int DEFAULT = 1;

    /**
     * The limit the control plane applied to this claim, on every answer to it — 200 and 204 alike.
     *
     * <p><b>A header and not a field</b>, because the answer that matters most carries no body: an
     * agent waiting at its limit receives 204, and has to learn from that very answer that the
     * limit went up. The hello carries the value too, but it is sent once per process, and a
     * lowered limit that reached the agent only at its next restart would not be a setting.
     */
    public static final String HEADER = "X-Vectispire-Max-Concurrent";

    /**
     * A stored value as the queue applies it.
     *
     * <p><b>Clamped, not refused</b>: the row was written before the bound existed, or by hand, and
     * refusing it would stop an agent from claiming anything over a value nobody on its side can
     * change. Zero or less reads as one rather than as "paused" — disabling an agent is a setting
     * of its own, and a limit of zero that silently stopped a fleet would be the second way to say
     * it, found by nobody.
     */
    public static int effective(Integer stored) {
        if (stored == null || stored < MIN) {
            return DEFAULT;
        }
        return Math.min(stored, MAX);
    }

    /**
     * A value an administrator asks for, or the reason it is refused.
     *
     * <p>Refused rather than clamped, unlike {@link #effective}: the person asking is there to read
     * the answer, and an agent set to 50 that quietly runs 16 is a setting that lies.
     */
    public static Optional<String> refusal(int requested) {
        if (requested < MIN || requested > MAX) {
            return Optional.of("max_concurrent must be between " + MIN + " and " + MAX + ", not " + requested + ".");
        }
        return Optional.empty();
    }

    /**
     * The header's value as the agent reads it, or empty when absent or unreadable.
     *
     * <p>Empty rather than a default: an older control plane sends no header, and the agent then
     * keeps the value its hello received — which is exactly what it knew before.
     */
    public static OptionalInt parse(String header) {
        if (header == null || header.isBlank()) {
            return OptionalInt.empty();
        }
        try {
            return OptionalInt.of(effective(Integer.parseInt(header.trim())));
        } catch (NumberFormatException unreadable) {
            return OptionalInt.empty();
        }
    }
}
