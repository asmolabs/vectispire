package com.asmolabs.vectispire.core.services;

/**
 * Raised when a deployment key would travel unprotected.
 *
 * <p>Its own class so the API answers 412 rather than 500: the agent is correctly configured
 * and the queue is healthy — what is missing is TLS in front of the control plane, or a
 * sealing key the agent is too old to announce. Both are an operator's fix, and neither is a
 * fault in this process.
 */
public class InsecureCredentialTransportException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public InsecureCredentialTransportException() {
        super("This agent receives deployment keys, which requires an encrypted link or a sealing key.");
    }
}
