package com.asmolabs.vectispire.common.domain.plugins;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;

/**
 * A plugin manifest refused, with the reason the platform governor reads on the registration form.
 * An {@link InvalidInputException}, so a route answers 400 without a mapping of its own.
 */
public class InvalidPluginException extends InvalidInputException {

    public InvalidPluginException(String message) {
        super(message);
    }
}
