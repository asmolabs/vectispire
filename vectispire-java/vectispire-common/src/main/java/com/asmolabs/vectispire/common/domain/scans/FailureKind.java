package com.asmolabs.vectispire.common.domain.scans;

import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Locale;
import java.util.Set;

/**
 * Whether a scan that could not run is worth another attempt.
 *
 * <p><b>Two answers, and the default is the one that retries.</b> A host key that changed, a
 * deployment key the forge refuses, a repository that is not there, a credential that will not open,
 * a sub-path the clone does not hold, a URL the clone's own guard refuses: another attempt meets the
 * same refusal, and spending three of them — in seconds, with one agent that retakes the scan at its
 * next poll — only delays the reason reaching the screen. Everything else — the network, a timeout,
 * a daemon that did not answer, a lease that lapsed, and whatever nobody classified — may pass on the
 * next attempt, so it waits and retries. Reading an unknown failure as permanent would fail a scan for
 * good over a passing incident; reading a permanent one as transient costs three attempts and a
 * quarter of an hour. The second mistake is the cheaper one, so it is the one made when in doubt.
 *
 * <p><b>Decided where the failure is known, from its type.</b> The executor that failed holds the
 * exception; the kind travels beside the reason in an agent's report, and the built-in worker decides
 * it in place, from the same exceptions, with {@link #of}. Nothing reads it back out of the reason's
 * words: the reason is scrubbed, cut, and written for a person.
 */
public enum FailureKind {
    PERMANENT("permanent"),
    TRANSIENT("transient");

    private final String wireName;

    FailureKind(String wireName) {
        this.wireName = wireName;
    }

    /** The value of a failure report's {@code kind}. */
    public String wireName() {
        return wireName;
    }

    /**
     * The kind a report names.
     *
     * <p><b>Absent is transient</b>: an agent older than the field reports what it always reported,
     * and its failures keep the rule they had — the attempt counted, the scan back in the queue. An
     * unknown value is transient too, for the same reason an unknown failure is: a later agent's word
     * this version cannot read must not fail a scan for good.
     */
    public static FailureKind fromWire(String value) {
        if (value != null && PERMANENT.wireName.equals(value.trim().toLowerCase(Locale.ROOT))) {
            return PERMANENT;
        }
        return TRANSIENT;
    }

    /**
     * The kind a failure declares, looked for along its causes; {@link #TRANSIENT} when none does.
     *
     * <p>Along the causes because the failure that knows is rarely the outermost: a clone refused
     * inside the runner may reach the caller wrapped by whatever ran it. The first declaration wins,
     * which is the one nearest the caller — a wrapper that declares something knows more than what it
     * wraps.
     */
    public static FailureKind of(Throwable failure) {
        Set<Throwable> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Throwable cause = failure; cause != null && seen.add(cause); cause = cause.getCause()) {
            if (cause instanceof ClassifiedFailure classified && classified.failureKind() != null) {
                return classified.failureKind();
            }
        }
        return TRANSIENT;
    }
}
