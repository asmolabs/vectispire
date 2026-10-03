package com.asmolabs.vectispire.core.forges.internal;

import com.asmolabs.vectispire.common.domain.forges.DiscoveryReason;

/** A listing that cannot go on, with the reason the discovery ends on and the sentence an administrator reads. */
public class ForgeListingException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final DiscoveryReason reason;

    public ForgeListingException(DiscoveryReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public DiscoveryReason reason() {
        return reason;
    }
}
