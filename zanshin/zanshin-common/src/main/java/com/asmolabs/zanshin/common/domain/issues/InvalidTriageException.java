package com.asmolabs.zanshin.common.domain.issues;

/**
 * A triage request that cannot be recorded.
 *
 * <p>The message is meant to be shown as it is: it is the person doing the triage who needs to
 * know why their decision was refused, and "validation error" tells them nothing.
 */
public class InvalidTriageException extends RuntimeException {

    public InvalidTriageException(String message) {
        super(message);
    }
}
