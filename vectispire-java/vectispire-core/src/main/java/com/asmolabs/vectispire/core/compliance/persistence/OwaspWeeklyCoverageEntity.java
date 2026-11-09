package com.asmolabs.vectispire.core.compliance.persistence;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;

/**
 * One OWASP category of one target, as the grid read it in one ISO week.
 *
 * <p>The reasoning is in V67: the state cannot be reconstructed afterwards, so it is recorded. The
 * target is named by kind and identifier, with no foreign key; {@code OwaspCoveragePurge} removes a
 * deleted target's rows in the deleting transaction.
 *
 * <p><b>V67 says both counts are zero unless the category was measured; the rows read otherwise.</b> An
 * open finding counts wherever the settings measure its type, whatever examined the target since
 * ({@code FINDINGS}), and rows written before 0.11.0 kept a never-scanned target {@code NOT_MEASURED}
 * with the findings the grid would count. A reader combines the rows with {@code
 * OwaspCoverage.acrossTargets}, which reads both; summing the states without the rule would count a
 * target nothing can examine for a category — {@code NOT_COVERED}, an image for secrets — against it.
 */
@Entity
@Table(name = "t_owasp_weekly_coverage")
public class OwaspWeeklyCoverageEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    private Long id;

    /** The Monday at 00:00 UTC — {@code CoverageWeek.startOf}. */
    @Column(name = "week_start", nullable = false)
    private Instant weekStart;

    /** {@code repository} or {@code container}, as grants and gate policies spell them. */
    @Column(name = "target_kind", length = 16, nullable = false)
    private String targetKind;

    @Column(name = "target_id", nullable = false)
    private long targetId;

    /** {@code A01} to {@code A10}. */
    @Column(name = "category", length = 3, nullable = false)
    private String category;

    /** The name of an {@code OwaspCoverage.State}. */
    @Column(name = "state", length = 16, nullable = false)
    private String state;

    @Column(name = "open_count", nullable = false)
    private long openCount;

    @Column(name = "settled_count", nullable = false)
    private long settledCount;

    @Column(name = "captured_at", nullable = false)
    private Instant capturedAt;

    public Long getId() {
        return id;
    }

    public Instant getWeekStart() {
        return weekStart;
    }

    public void setWeekStart(Instant weekStart) {
        this.weekStart = weekStart;
    }

    public String getTargetKind() {
        return targetKind;
    }

    public void setTargetKind(String targetKind) {
        this.targetKind = targetKind;
    }

    public long getTargetId() {
        return targetId;
    }

    public void setTargetId(long targetId) {
        this.targetId = targetId;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public long getOpenCount() {
        return openCount;
    }

    public void setOpenCount(long openCount) {
        this.openCount = openCount;
    }

    public long getSettledCount() {
        return settledCount;
    }

    public void setSettledCount(long settledCount) {
        this.settledCount = settledCount;
    }

    public Instant getCapturedAt() {
        return capturedAt;
    }

    public void setCapturedAt(Instant capturedAt) {
        this.capturedAt = capturedAt;
    }
}
