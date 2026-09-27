package com.asmolabs.vectispire.common.domain.sarif;

/**
 * A SARIF document refused, with a reason meant to be read by whoever produced it.
 *
 * <p>An {@link IllegalArgumentException} so that an import route answers 400 without a mapping of
 * its own: the document is the caller's, and the caller can fix it. On the scanning side the same
 * refusal fails the plugin's step, whose result stays absent (decision 0007).
 */
public class InvalidSarifException extends IllegalArgumentException {

    public InvalidSarifException(String message) {
        super(message);
    }
}
