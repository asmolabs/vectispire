package com.asmolabs.vectispire.agent.kubernetes;

/**
 * The API server refused, failed, or could not be reached.
 *
 * @param status the HTTP status it answered, or 0 when there was no answer to read one from
 */
public class KubernetesException extends RuntimeException {

    private final int status;

    public KubernetesException(String message, int status) {
        super(message);
        this.status = status;
    }

    public KubernetesException(String message, Throwable cause) {
        super(message, cause);
        this.status = 0;
    }

    public int status() {
        return status;
    }
}
