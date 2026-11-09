package com.asmolabs.vectispire.core.plugins;

/**
 * A coverage or test report past its route's ceiling, found by the service — the body filter refuses
 * a declared length first; this is the same limit, held where the bytes are read.
 */
public class ReportTooLargeException extends RuntimeException {

    public ReportTooLargeException(String message) {
        super(message);
    }
}
