package com.asmolabs.vectispire.core.access;

import com.asmolabs.vectispire.core.access.persistence.AccountRequestEntity;
import java.time.Instant;

/**
 * An account change waiting for a second administrator, as the screen shows it — never the password hash it
 * carries.
 *
 * @param kind {@code create} or {@code change}
 * @param accountId the account a change is about; null for a creation
 * @param heldRole the role the account held when the change was filed; null for a creation
 * @param requestedRole the role asked for; null for a change that keeps the role
 * @param passwordReset whether the change sets a password the requester typed — a reset, or a creation's
 */
public record AccountRequestView(
        Long id,
        String kind,
        Long accountId,
        String username,
        String email,
        String displayName,
        String heldRole,
        String requestedRole,
        boolean passwordReset,
        Long requestedById,
        String requestedBy,
        Instant requestedAt) {

    static AccountRequestView of(AccountRequestEntity request) {
        return new AccountRequestView(
                request.getId(),
                request.getKind(),
                request.getAccountId(),
                request.getUsername(),
                request.getEmail(),
                request.getDisplayName(),
                request.getHeldRole(),
                request.getRequestedRole(),
                request.getPasswordHash() != null,
                request.getRequestedById(),
                request.getRequestedBy(),
                request.getRequestedAt());
    }
}
