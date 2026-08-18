package com.asmolabs.zanshin.common.scanning;

/** A clone that did not happen, with git's own output kept for whoever needs the detail. */
public class CloneFailureException extends RuntimeException {

    private final String stderr;

    CloneFailureException(String message, String stderr) {
        super(message);
        this.stderr = stderr == null ? "" : stderr;
    }

    public String stderr() {
        return stderr;
    }
}
