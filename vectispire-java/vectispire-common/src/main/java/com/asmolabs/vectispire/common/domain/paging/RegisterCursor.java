package com.asmolabs.vectispire.common.domain.paging;

import java.time.Instant;
import java.util.Optional;

/**
 * Where a register's next page starts.
 *
 * <h2>Why a cursor and not an offset, on these registers in particular</h2>
 *
 * <p><b>Visibility is applied after the read here, not in the query.</b> That is a deliberate rule
 * of this codebase — whose estate a row belongs to has one implementation and it is not in SQL —
 * and it makes an offset meaningless: {@code offset=100} counts rows the caller may not see, so
 * the second page of a restricted reader starts in the middle of somebody else's estate and the
 * boundary moves every time a pipeline writes a verdict.
 *
 * <p>A cursor names a <em>row</em> instead of a count. Rows inserted while somebody reads do not
 * shift what comes next, which is the property an audit register needs: a reader paging through
 * a year of verdicts must not be handed the same one twice, nor skip one, because the estate kept
 * working while they read.
 *
 * <h2>The instant is not enough</h2>
 *
 * <p>A pipeline writes several verdicts in the same millisecond. A cursor carrying only the
 * instant either returns the ties twice or drops them, depending on which comparison you pick;
 * carrying the row's identifier as well makes the order total, and the identifier does not need
 * to mean anything for that.
 *
 * @param at the sort instant of the last row of the previous page
 * @param id that row's identifier, breaking ties on {@code at}
 */
public record RegisterCursor(Instant at, String id) {

    /** The separator, chosen because neither half can contain it. */
    private static final char SEPARATOR = ':';

    /**
     * Reads a cursor a client sent back, or nothing.
     *
     * <p><b>Unreadable reads as absent, which means "start at the beginning".</b> The alternative
     * is refusing the request, and that trades a first page for an error on a value the client
     * never composed itself — it echoed back what the server handed it. A cursor is a position,
     * not an assertion: the worst a wrong one can do is start the reader where they already were.
     */
    public static Optional<RegisterCursor> parse(String encoded) {
        if (encoded == null || encoded.isBlank()) {
            return Optional.empty();
        }
        int split = encoded.indexOf(SEPARATOR);
        if (split <= 0 || split == encoded.length() - 1) {
            return Optional.empty();
        }
        try {
            return Optional.of(new RegisterCursor(
                    Instant.ofEpochMilli(Long.parseLong(encoded.substring(0, split))),
                    encoded.substring(split + 1)));
        } catch (NumberFormatException unreadable) {
            return Optional.empty();
        }
    }

    /**
     * The form a client sends back.
     *
     * <p>Epoch milliseconds rather than an ISO instant: the stores hold these timestamps to the
     * millisecond — SQLite keeps an {@code Instant} as an integer of them — so an encoding with
     * more precision than the column would hand back a cursor that falls between two rows.
     */
    public String encoded() {
        return at.toEpochMilli() + String.valueOf(SEPARATOR) + id;
    }
}
