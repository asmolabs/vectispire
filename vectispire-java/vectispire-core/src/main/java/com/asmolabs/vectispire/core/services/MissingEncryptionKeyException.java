package com.asmolabs.vectispire.core.services;

/**
 * Raised at encryption time, never at startup.
 *
 * <p>Its own class so the API can answer 412 rather than 500: a deployment with no key is
 * misconfigured, not broken, and the distinction is the difference between an operator
 * fixing an environment variable and an operator reading a stack trace.
 */
public class MissingEncryptionKeyException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public MissingEncryptionKeyException() {
        super("No encryption key is configured: a new value cannot be encrypted. "
                + "Generate one with `openssl rand -base64 32` and set ENCRYPTION_KEY before saving a secret.");
    }
}
