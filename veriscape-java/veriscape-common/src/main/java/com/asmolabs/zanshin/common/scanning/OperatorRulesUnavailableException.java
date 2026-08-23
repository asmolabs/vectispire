package com.asmolabs.zanshin.common.scanning;

/** A rule source was named and cannot be used. Refusing to scan is the point. */
public class OperatorRulesUnavailableException extends RuntimeException {

    public OperatorRulesUnavailableException(String message) {
        super(message);
    }
}
