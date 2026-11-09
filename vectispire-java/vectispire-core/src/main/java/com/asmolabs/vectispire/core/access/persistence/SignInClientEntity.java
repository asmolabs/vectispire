package com.asmolabs.vectispire.core.access.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * A client that has signed in to an account — see {@code LoginThrottle#knownClientKey}.
 *
 * <p>Keyed by a digest of the account and the client's bucket rather than holding the address: the
 * question asked of this table is only ever "has this client signed in to this account", and a table
 * that answers it does not also have to be a record of where every account signs in from.
 */
@Entity
@Table(name = "t_sign_in_client")
public class SignInClientEntity {

    @Id
    @Column(name = "client_key", length = 64, nullable = false)
    private String clientKey;

    @Column(name = "account_id", nullable = false)
    private Long accountId;

    @Column(name = "last_signed_in_at", nullable = false)
    private Instant lastSignedInAt;

    public String getClientKey() {
        return clientKey;
    }

    public void setClientKey(String clientKey) {
        this.clientKey = clientKey;
    }

    public Long getAccountId() {
        return accountId;
    }

    public void setAccountId(Long accountId) {
        this.accountId = accountId;
    }

    public Instant getLastSignedInAt() {
        return lastSignedInAt;
    }

    public void setLastSignedInAt(Instant lastSignedInAt) {
        this.lastSignedInAt = lastSignedInAt;
    }
}
