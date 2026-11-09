package com.asmolabs.vectispire.common.domain.apikeys;

/** A key that cannot be issued as requested. The message is shown to whoever asked. */
public class InvalidApiKeyException extends RuntimeException {

    public InvalidApiKeyException(String message) {
        super(message);
    }
}
