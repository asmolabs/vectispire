package com.asmolabs.vectispire.common.domain.net;

/** The URL is not a destination Vectispire will call. */
public class UnsafeUrlException extends RuntimeException {

    public UnsafeUrlException(String message) {
        super(message);
    }
}
