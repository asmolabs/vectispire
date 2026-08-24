package com.asmolabs.vectispire.core.repositories;

import com.asmolabs.vectispire.common.domain.issues.Severity;
import java.util.Arrays;
import java.util.stream.Collectors;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.JpaSort;

/**
 * How a backlog is ordered when nobody asked for anything else.
 *
 * <p><b>Severity is stored as text, so ordering by the column is alphabetical</b> — which puts
 * {@code critical, high, low, medium, negligible} in that order and buries the mediums under
 * the lows. Every ordering by severity therefore has to go through a rank, and this is the one
 * place that rank is written for the backlog.
 *
 * <p><b>The rank comes from the enum, not from a list kept alongside it.</b> {@link Severity} is
 * declared worst first precisely so that its natural order is the comparison rank; deriving the
 * SQL from {@code values()} means a severity added tomorrow is ranked by where it is declared,
 * and cannot be forgotten here. A hand-written {@code case} is how the same list ends up in two
 * places disagreeing — and the disagreement would be invisible, because both orderings look
 * plausible on screen.
 */
public final class IssueOrdering {

    /**
     * Most severe first, then most recently seen.
     *
     * <p>The tie-breaks matter as much as the first term: within one severity an operator is
     * looking at a list that must not reshuffle between two page loads, and {@code id} makes the
     * order total. Without it, a page boundary can show the same issue twice and skip another.
     */
    public static final Sort MOST_SEVERE_FIRST = JpaSort.unsafe(Sort.Direction.ASC, "(" + severityRank() + ")")
            .and(Sort.by(Sort.Order.desc("lastSeenAt"), Sort.Order.desc("id")));

    private IssueOrdering() {}

    /**
     * A {@code case} mapping each stored severity to its position in the enum.
     *
     * <p>The {@code else} catches a value no version of Vectispire writes — a row from an older
     * schema, or a scanner label that reached the column. It sorts last rather than first: an
     * unrecognised severity must not head a backlog it says nothing about.
     */
    private static String severityRank() {
        return Arrays.stream(Severity.values())
                .map(severity -> "when '" + severity.wireName() + "' then " + severity.ordinal())
                .collect(Collectors.joining(" ", "case severity ", " else " + Severity.values().length + " end"));
    }
}
