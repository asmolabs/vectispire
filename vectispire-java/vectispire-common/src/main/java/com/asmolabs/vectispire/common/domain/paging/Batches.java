package com.asmolabs.vectispire.common.domain.paging;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * A list cut into consecutive batches — an {@code in} list kept under every engine's bind-parameter
 * ceiling, a bulk statement kept to a size a lock can hold.
 *
 * <p>Forty-odd lookups wrote the same {@code subList} loop by hand, each with its own spelling of the
 * bound; one of them reversing the {@code Math.min} is how an off-by-one gets in unnoticed.
 */
public final class Batches {

    private Batches() {}

    /**
     * The batches of at most {@code size} items, in order; none for an empty list.
     *
     * <p>Unmodifiable views of {@code items}, not copies: a caller hands each to one statement and
     * moves on, and a copy would refuse the {@code null} a view passes through as the loops did.
     */
    public static <T> List<List<T>> of(List<T> items, int size) {
        if (size <= 0) {
            throw new IllegalArgumentException("A batch holds at least one item: " + size + ".");
        }
        List<List<T>> batches = new ArrayList<>();
        for (int from = 0; from < items.size(); from += size) {
            batches.add(Collections.unmodifiableList(items.subList(from, Math.min(from + size, items.size()))));
        }
        return batches;
    }
}
