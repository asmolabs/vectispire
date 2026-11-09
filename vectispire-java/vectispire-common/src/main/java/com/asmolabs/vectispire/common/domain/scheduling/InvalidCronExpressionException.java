package com.asmolabs.vectispire.common.domain.scheduling;

/** The expression is not something one can schedule on. */
public class InvalidCronExpressionException extends RuntimeException {

    public InvalidCronExpressionException(String message) {
        super(message);
    }
}
