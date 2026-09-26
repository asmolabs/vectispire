package com.asmolabs.vectispire.core.scanning;

/**
 * Raised when a delegated credential would leave without a sealing key the agent proved.
 *
 * <p>Its own class so the API answers 412 rather than 500: the queue is healthy and the scan is
 * back in it — what is missing is an operator's step, and the message names which. It replaced
 * {@code InsecureCredentialTransportException}, which accepted TLS as a substitute; decision 0031
 * says why it is not one.
 */
public class CredentialWithheldException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /** @param notPinned true when no signing key is pinned for the agent, which is the first thing to fix */
    public CredentialWithheldException(boolean notPinned) {
        super(notPinned
                ? "This agent receives delegated credentials, which are only ever sealed for a sealing key signed "
                        + "with the agent's pinned signing key — and no signing key is pinned for it. Pin one from "
                        + "the agents administration screen and configure its private half as "
                        + "vectispire.agent.signing-key."
                : "This agent receives delegated credentials, which are only ever sealed for a sealing key signed "
                        + "with the agent's pinned signing key — and it has announced none that verified. An agent "
                        + "announces one at start; one older than this version cannot, and must be updated.");
    }
}
