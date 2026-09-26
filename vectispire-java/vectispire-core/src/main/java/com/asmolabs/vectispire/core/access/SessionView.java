package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.core.access.persistence.SessionEntity;
import java.time.Instant;

/**
 * A session as the layers above the services hold it: the row's properties, not the row.
 *
 * <p>{@link #tokenHash} identifies it — to revoke it, or to spare it when the account's other
 * sessions are closed. The token itself is not here and never was: the store holds its hash only,
 * and the one copy of the token travels in {@code AuthService.IssuedSession} for the length of the
 * request that opened it.
 */
public record SessionView(
        String tokenHash,
        Long userId,
        Instant createdAt,
        Instant lastSeenAt,
        Instant expiresAt,
        String userAgent,
        String ipAddress) {

    public static SessionView of(SessionEntity session) {
        return new SessionView(
                session.getTokenHash(),
                session.getUserId(),
                session.getCreatedAt(),
                session.getLastSeenAt(),
                session.getExpiresAt(),
                session.getUserAgent(),
                session.getIpAddress());
    }
}
