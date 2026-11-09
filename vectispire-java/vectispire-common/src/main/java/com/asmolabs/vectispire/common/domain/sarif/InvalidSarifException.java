package com.asmolabs.vectispire.common.domain.sarif;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;

/**
 * A SARIF document refused, with a reason meant to be read by whoever produced it.
 *
 * <p>An {@link InvalidInputException} so that an import route answers 400 without a mapping of
 * its own: the document is the caller's, and the caller can fix it. On the scanning side the same
 * refusal fails the plugin's step, whose result stays absent (decision 0007).
 */
public class InvalidSarifException extends InvalidInputException {

    public InvalidSarifException(String message) {
        super(message);
    }
}
