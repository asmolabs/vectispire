package com.asmolabs.vectispire.core.plugins;

/**
 * A SARIF document past the import ceiling, found by the service — the route's body filter refuses
 * a declared length first; this is the same limit, held where the bytes are read.
 */
public class SarifTooLargeException extends RuntimeException {

    public SarifTooLargeException(String message) {
        super(message);
    }
}
