package com.asmolabs.vectispire.core.platform.web;

import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A failure nobody wrote a sentence for: logged in full under a reference, answered with the
 * reference alone.
 *
 * <p><b>The message stays in the log.</b> An exception nobody meant for a client carries whatever
 * its thrower put in it — a SQL fragment, a column name, a library's "For input string", a path on
 * the host. Answering it verbatim publishes the implementation to whoever can make it fail; answering
 * nothing leaves the operator a 500 they cannot find in the log. The reference is what joins the two:
 * the caller quotes it, the operator searches for it.
 */
final class UnexpectedFailure {

    private static final Logger log = LoggerFactory.getLogger(UnexpectedFailure.class);

    /** The member of the problem that carries the reference. */
    static final String REFERENCE = "correlationId";

    private UnexpectedFailure() {}

    /** Logs the failure and returns the reference it was logged under. */
    static String record(String method, String path, Throwable error) {
        String reference = UUID.randomUUID().toString();
        log.error("Unexpected failure {} on {} {}", reference, method, path, error);
        return reference;
    }

    static String detail(String reference) {
        return "An unexpected error occurred. Quote reference " + reference + " to your administrator.";
    }
}
