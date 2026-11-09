package com.asmolabs.vectispire.core.maintenance.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * A job that has run on this database, and must not run again.
 *
 * <p>Mapped so that {@code ddl-auto: validate} checks the table against it; never saved — the row
 * is written by one insert whose primary key arbitrates ({@link OneShotJobRepository#claim}).
 */
@Entity
@Table(name = "t_one_shot_job")
public class OneShotJobEntity {

    @Id
    @Column(name = "name", nullable = false, length = 64)
    private String name;

    @Column(name = "ran_at", nullable = false)
    private Instant ranAt;

    public String getName() {
        return name;
    }

    public Instant getRanAt() {
        return ranAt;
    }
}
