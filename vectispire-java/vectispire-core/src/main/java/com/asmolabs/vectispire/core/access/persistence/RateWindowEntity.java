package com.asmolabs.vectispire.core.access.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * How many requests one subject made in one fixed window of one limit, counted by every instance
 * together — see {@code RateWindows}.
 *
 * <p>Mapped for the schema's validation and the reads; every write is a statement of {@link
 * RateWindowRepository}, never a {@code save}, which would read and then write and lose the hits
 * another instance made in between.
 */
@Entity
@Table(name = "t_rate_window")
public class RateWindowEntity {

    @Id
    @Column(name = "window_key", nullable = false, length = 120)
    private String windowKey;

    @Column(name = "hits", nullable = false)
    private int hits;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    public String getWindowKey() {
        return windowKey;
    }

    public int getHits() {
        return hits;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }
}
