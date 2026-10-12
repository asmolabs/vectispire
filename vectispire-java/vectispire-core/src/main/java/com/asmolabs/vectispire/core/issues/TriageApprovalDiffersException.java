package com.asmolabs.vectispire.core.issues;

import com.asmolabs.vectispire.common.domain.errors.ConflictException;
import com.asmolabs.vectispire.common.domain.issues.TriageStatus;
import java.util.Map;

/**
 * An approval granting another status than the one the request asked for: 409, with the type {@code
 * urn:vectispire:problem:triage-approval-differs} and the member {@code requestedStatus}.
 *
 * <p><b>Why a refusal and not the approver's choice.</b> A queued decision used to keep its
 * justification, comment and review date and drop its status, so whoever approved chose one: a
 * tracker's "Won't Fix" — an accepted risk, exposed and known — could be granted as {@code
 * not_affected}, and the signed VEX documents then said the product was not exposed, under the
 * approval of somebody who had been asked something else (decision 0041). An approver who disagrees
 * turns the request down — back to {@code under_review} or {@code affected} — and the decision they
 * then take is theirs, under their own name, rather than the requester's request rewritten.
 *
 * <p>A 409 rather than the 400 of the other triage refusals: the request is well formed, and the same
 * body succeeds on an issue that is not waiting for something else. The cause names it, so a screen can
 * offer the requested status rather than parse the sentence.
 */
public final class TriageApprovalDiffersException extends ConflictException {

    /** The token the problem's {@code type} ends with, published in the route's description. */
    public static final String CAUSE = "triage-approval-differs";

    /** @param requested as stored: a status this version does not know is still named, never a 500 */
    TriageApprovalDiffersException(String requested, TriageStatus granted) {
        super("This request asks for " + requested + ": approve it as " + requested
                        + ", or turn it down (under_review or affected) and record your own decision. It cannot be "
                        + "granted as " + granted.wireName() + ".",
                CAUSE,
                Map.of("requestedStatus", requested));
    }
}
