package com.asmolabs.vectispire.core.access.web.security;

/**
 * A body past its route's ceiling, found while it was being read.
 *
 * <p>Thrown by {@code RequestBodyLimitFilter} as the counted stream passes the ceiling, and mapped to
 * 413 by {@code ApiExceptionHandler}. <b>Here, beside the other exceptions the error handler maps, and
 * not nested in the filter</b>, where it used to be: the handler sits in another module, and naming a
 * class of {@code access}'s filter chain made the chain part of what {@code access} publishes without
 * saying so (decision 0028 listed it for step 5). The chain stays {@code access}'s own; what a caller
 * outside it may catch is in the named interface.
 */
public class RequestBodyTooLargeException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final long ceiling;

    public RequestBodyTooLargeException(long ceiling) {
        super("The request body is larger than the " + ceiling + " bytes this route accepts.");
        this.ceiling = ceiling;
    }

    public long ceiling() {
        return ceiling;
    }
}
