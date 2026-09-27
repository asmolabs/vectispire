package com.asmolabs.vectispire.common.domain.plugins;

/**
 * A plugin manifest refused, with the reason the platform governor reads on the registration form.
 * An {@link IllegalArgumentException}, so a route answers 400 without a mapping of its own.
 */
public class InvalidPluginException extends IllegalArgumentException {

    public InvalidPluginException(String message) {
        super(message);
    }
}
