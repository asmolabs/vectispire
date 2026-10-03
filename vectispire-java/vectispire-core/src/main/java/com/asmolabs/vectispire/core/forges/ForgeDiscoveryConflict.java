package com.asmolabs.vectispire.core.forges;

import com.asmolabs.vectispire.common.domain.errors.ConflictException;
import java.util.Map;

/** A discovery refused for the state the connection is in (decision 0037 §3), answered 409 with its cause. */
public class ForgeDiscoveryConflict extends ConflictException {

    private static final long serialVersionUID = 1L;

    /** Why. */
    public enum Cause {
        /** A discovery of this connection is pending or running: it is the one to poll; {@code discoveryId} names it. */
        IN_PROGRESS("forge-discovery-in-progress"),
        /** This version lists no repositories of this forge yet — GitHub's adapter is lot D4. */
        UNSUPPORTED("forge-discovery-unsupported"),
        /**
         * Repositories are selected and imported from a discovery that ended with something to choose from —
         * completed, or partial — and this one is pending, running or failed; {@code state} says which.
         */
        NOT_SELECTABLE("forge-discovery-not-selectable"),
        /**
         * A newer discovery of the connection has ended: the snapshot now describes it, and selecting from the
         * older one would offer what it no longer lists. {@code latestDiscoveryId} names the one to select from.
         */
        SUPERSEDED("forge-discovery-superseded");

        private final String token;

        Cause(String token) {
            this.token = token;
        }

        public String token() {
            return token;
        }
    }

    public ForgeDiscoveryConflict(Cause cause, String message) {
        super(message, cause.token());
    }

    public ForgeDiscoveryConflict(Cause cause, String message, Map<String, ?> members) {
        super(message, cause.token(), members);
    }
}
