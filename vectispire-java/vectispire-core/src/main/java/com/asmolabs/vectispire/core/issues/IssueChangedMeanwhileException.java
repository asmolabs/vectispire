package com.asmolabs.vectispire.core.issues;

import com.asmolabs.vectispire.common.domain.errors.ConflictException;

/**
 * A triage refused because the issue changed between its read and its write — a scan folded it, or
 * somebody else decided first: 409, with the type {@code urn:vectispire:problem:issue-changed-meanwhile}.
 *
 * <p><b>Refused rather than written over.</b> The triage read the row and saved it whole, so what had
 * been committed in between — a scan's resolution, another person's decision — was put back to what this
 * request had read, and nothing said so. The issue's revision (V89) now makes the second writer fail; the
 * person reads the issue as it is and decides again. Nothing was written: the whole decision rolls back,
 * the history row with it.
 */
public final class IssueChangedMeanwhileException extends ConflictException {

    /** The token the problem's {@code type} ends with, published in the route's description. */
    public static final String CAUSE = "issue-changed-meanwhile";

    IssueChangedMeanwhileException() {
        super("The issue changed while this decision was being recorded — a scan or another person wrote it first. "
                + "Nothing was recorded: read the issue again and repeat the decision.", CAUSE);
    }
}
