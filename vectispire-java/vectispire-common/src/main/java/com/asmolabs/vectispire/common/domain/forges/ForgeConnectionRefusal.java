package com.asmolabs.vectispire.common.domain.forges;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;

/**
 * A forge connection refused for what its address or its token is — not for the request's form.
 *
 * <p><b>Two of them are a security event</b> (decision 0037 §2, {@code VECTI-SEC-036}): a destination the
 * outbound guard blocks — a base URL aimed at the internal network, the metadata endpoint or the
 * database — and a token broader than the read-only scopes a connection is for. Both are how an SSRF or a
 * credential-harvesting attempt shows itself, and a SOC wants them whether or not the administrator who
 * typed them meant harm. A token the forge rejects, a server too old or unreachable are an
 * administrator's to fix and nobody else's business.
 */
public class ForgeConnectionRefusal extends InvalidInputException {

    private static final long serialVersionUID = 1L;

    /** Why, as far as a SOC is concerned. */
    public enum Reason {
        /** The outbound guard refused the address: internal under {@code PUBLIC_ONLY}, link-local, reserved. */
        DESTINATION_BLOCKED(true),
        /** The forge reports a scope outside the read-only allow-list, or a credential no connection accepts. */
        SCOPE_REFUSED(true),
        /** The forge refused the token: wrong, expired, revoked. */
        TOKEN_REJECTED(false),
        /** The token lacks what a discovery needs, {@code read_api} on GitLab. */
        SCOPE_MISSING(false),
        /** The server is older than the oldest version the adapters are written for. */
        VERSION_UNSUPPORTED(false),
        /** The owner a GitHub connection names does not exist, or is not visible with this token. */
        OWNER_NOT_FOUND(false),
        /** No usable answer: a network failure, a TLS failure, a 5xx, a body that is not the API's. */
        UNREACHABLE(false);

        private final boolean signalled;

        Reason(boolean signalled) {
            this.signalled = signalled;
        }

        /** Whether this refusal is signalled to the SIEM as {@code VECTI-SEC-036}. */
        public boolean signalled() {
            return signalled;
        }
    }

    private final Reason reason;

    public ForgeConnectionRefusal(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public ForgeConnectionRefusal(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }
}
