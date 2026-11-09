package com.asmolabs.vectispire.common.domain.paging;

import com.asmolabs.vectispire.common.domain.errors.InvalidInputException;
import java.util.List;
import java.util.Optional;

/**
 * A page a list route was asked for: at most {@code limit} rows, from the {@code offset}-th.
 *
 * <p><b>One rule for every list that takes {@code limit} and {@code offset} and refuses what it cannot
 * serve.</b> The forge discovery's repositories and the import selection each carried a copy of it; the
 * inventory lists that became pageable in 0.11.1 would have been the third to the sixth, and the copies
 * would have drifted the way the gate's two severity parsers did. A limit past {@link #MAX_LIMIT} is a
 * 400 rather than a silent clamp: a client asking for a thousand and handed five hundred reads the end
 * of the list where there is none, while one refused learns the bound from the sentence.
 *
 * <p><b>An offset is a multiple of the limit</b>, as on the forge routes that came first: the pages are
 * then the same cut whoever asks, and a client cannot ask for a window straddling two of them.
 *
 * <p>The offset counts the rows the caller sees, never rows it may not: a route applies its visibility
 * before it windows, so the second page of a restricted reader starts at their twenty-first target, not
 * in the middle of someone else's estate.
 *
 * @param limit 1 to {@link #MAX_LIMIT}
 * @param offset zero or a multiple of {@code limit}
 */
public record ListWindow(int limit, int offset) {

    /** The largest page any list route hands out — the one figure the contract publishes for all of them. */
    public static final int MAX_LIMIT = 500;

    /** The {@code limit} parameter, as the routes that page on request describe it. */
    public static final String LIMIT_ON_REQUEST = "Rows per page, 1 to " + MAX_LIMIT + "; 400 beyond. Absent, with no "
            + "offset, the whole list is answered, as before paging existed.";

    /** The {@code offset} parameter, as the routes that page on request describe it. */
    public static final String OFFSET_ON_REQUEST = "Rows to skip, zero or a multiple of limit (0); read only with a "
            + "limit, 400 without one.";

    /**
     * @throws InvalidInputException a limit outside 1 to {@link #MAX_LIMIT}, an offset that is negative or not a
     *     multiple of the limit — with the sentence the caller reads
     */
    public ListWindow {
        if (limit < 1 || limit > MAX_LIMIT) {
            throw new InvalidInputException("The limit is between 1 and " + MAX_LIMIT + ".");
        }
        if (offset < 0 || offset % limit != 0) {
            throw new InvalidInputException("The offset is zero or a multiple of the limit.");
        }
    }

    /**
     * The window of a route that always pages: {@code defaultLimit} rows from the first when the caller named
     * neither.
     */
    public static ListWindow of(Integer limit, Integer offset, int defaultLimit) {
        return new ListWindow(limit == null ? defaultLimit : limit, offset == null ? 0 : offset);
    }

    /**
     * The window of a route that answered its whole list before it could page, and still does when asked
     * nothing: empty when neither parameter was given.
     *
     * <p><b>An offset alone is refused, not read with a default limit.</b> No limit is how a caller asks for
     * everything on these routes; an offset beside it would be "everything after the hundredth", a request
     * nobody sends on purpose and whose answer grows with the estate like the one paging exists to avoid.
     *
     * @throws InvalidInputException an offset without a limit, or a window {@link ListWindow} refuses
     */
    public static Optional<ListWindow> requested(Integer limit, Integer offset) {
        if (limit == null) {
            if (offset != null) {
                throw new InvalidInputException("An offset is read with a limit; without either, the whole list is "
                        + "answered.");
            }
            return Optional.empty();
        }
        return Optional.of(new ListWindow(limit, offset == null ? 0 : offset));
    }

    /** The zero-based page this window is, for a query that pages by number. */
    public int page() {
        return offset / limit;
    }

    /**
     * This window of rows already read, filtered and ordered — empty past the end, never a refusal: a page
     * past the last is how a client paging forward learns it has reached it.
     */
    public <T> List<T> of(List<T> rows) {
        if (offset >= rows.size()) {
            return List.of();
        }
        return List.copyOf(rows.subList(offset, Math.min(rows.size(), offset + limit)));
    }
}
