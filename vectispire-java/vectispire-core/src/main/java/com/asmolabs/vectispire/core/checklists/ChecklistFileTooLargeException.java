package com.asmolabs.vectispire.core.checklists;

/**
 * An uploaded proof past its ceiling, found by the service — the body filter refuses a declared length
 * first; this is the same limit, held where the bytes are stored. Answered 413.
 *
 * <p><b>In the filter's words, exactly.</b> One 413 answered two sentences: the filter's "larger than
 * the N bytes this route accepts" for a declared or counted body, and this one's "a proof is at most N
 * bytes; attach a larger document as a link" when the service found it — and the interface, which
 * refuses a large file before sending it, quotes the filter's. The filter answers first on every route
 * that reaches here, so its sentence is the one; this class says it too, rather than naming the
 * filter's exception, which is the access module's and which a service does not reach for. {@code
 * ChecklistFileTooLargeExceptionTest} fails when the two drift apart.
 */
public class ChecklistFileTooLargeException extends RuntimeException {

    public ChecklistFileTooLargeException(long ceiling) {
        super("The request body is larger than the " + ceiling + " bytes this route accepts.");
    }
}
