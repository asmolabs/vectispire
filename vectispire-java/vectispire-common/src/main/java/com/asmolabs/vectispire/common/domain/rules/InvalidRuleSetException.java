package com.asmolabs.vectispire.common.domain.rules;

/** An upload that cannot be stored as offered. The message is shown to the operator. */
public class InvalidRuleSetException extends RuntimeException {

    public InvalidRuleSetException(String message) {
        super(message);
    }
}
