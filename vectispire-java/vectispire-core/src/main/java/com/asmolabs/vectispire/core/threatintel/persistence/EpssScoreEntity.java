package com.asmolabs.vectispire.core.threatintel.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.util.Objects;

/**
 * One CVE's EPSS score, in one generation of FIRST's file — see {@code V45__epss_scores.sql} for why
 * scores are written under a generation, and {@code ThreatIntelSyncEntity.epssGeneration} for which
 * one is in use.
 *
 * <p>Mapped for the reads and the deletes; the rows are written by {@link EpssScoreBulkWrites}, many
 * to a statement, since one {@code persist} per row is 380,000 round trips.
 */
@Entity
@Table(name = "t_epss_score")
@IdClass(EpssScoreEntity.Key.class)
public class EpssScoreEntity {

    /** The composite key, as JPA wants it spelled: a class with the two fields, not a record. */
    public static class Key implements Serializable {

        private static final long serialVersionUID = 1L;

        private long generation;
        private String cveId;

        public Key() {}

        public Key(long generation, String cveId) {
            this.generation = generation;
            this.cveId = cveId;
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof Key key && key.generation == generation && Objects.equals(key.cveId, cveId);
        }

        @Override
        public int hashCode() {
            return Objects.hash(generation, cveId);
        }
    }

    @Id
    @Column(name = "generation", nullable = false)
    private long generation;

    @Id
    @Column(name = "cve_id", length = 32, nullable = false)
    private String cveId;

    @Column(name = "score", nullable = false)
    private double score;

    @Column(name = "percentile", nullable = false)
    private double percentile;

    public long getGeneration() {
        return generation;
    }

    public void setGeneration(long generation) {
        this.generation = generation;
    }

    public String getCveId() {
        return cveId;
    }

    public void setCveId(String cveId) {
        this.cveId = cveId;
    }

    public double getScore() {
        return score;
    }

    public void setScore(double score) {
        this.score = score;
    }

    public double getPercentile() {
        return percentile;
    }

    public void setPercentile(double percentile) {
        this.percentile = percentile;
    }
}
