package com.asmolabs.vectispire.core.compliance.persistence;

import com.asmolabs.vectispire.common.domain.access.Visibility;
import java.time.Instant;
import java.util.List;

/**
 * The weekly OWASP record as a reader reads it: summed over the targets they may see, in the database.
 *
 * <p><b>Grouped rather than read row by row.</b> A year of weeks over an estate of a thousand targets is
 * half a million rows; per week, category and state it is at most two thousand, whatever the estate.
 */
public interface OwaspWeeklyCoverageQueries {

    /**
     * Every recorded week in {@code [fromWeek, toWeek]}, narrowed to the targets {@code allowed}
     * permits. Weeks with no row for those targets are absent — not recorded, which the reader says.
     */
    List<OwaspWeeklyStateCount> sumByWeekCategoryAndState(Instant fromWeek, Instant toWeek, Visibility allowed);
}
