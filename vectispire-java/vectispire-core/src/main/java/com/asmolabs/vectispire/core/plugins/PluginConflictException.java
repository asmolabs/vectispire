package com.asmolabs.vectispire.core.plugins;

/**
 * A plugin id, or a source's slug or key, already taken. 409: nothing about the request is malformed,
 * and the id is an identity — reusing one would hand an existing backlog's triage to other code.
 */
public class PluginConflictException extends RuntimeException {

    public PluginConflictException(String message) {
        super(message);
    }
}
