package com.asmolabs.zanshin.common.domain.net;

/** The URL is not a destination Zanshin will call. */
public class UnsafeUrlException extends RuntimeException {

    public UnsafeUrlException(String message) {
        super(message);
    }
}
