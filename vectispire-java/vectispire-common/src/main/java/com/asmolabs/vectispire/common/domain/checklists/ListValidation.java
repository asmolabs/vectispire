package com.asmolabs.vectispire.common.domain.checklists;

import java.util.List;
import java.util.Objects;

/**
 * A list data validation of a sheet: the cells it covers, and the formula naming the allowed values.
 *
 * @param source the list's formula as written — a range ({@code Values!$A$1:$A$2}), a defined
 *     name, or a literal list ({@code "Yes,No"}) — without a leading {@code =}
 * @param fromExtension read from the {@code x14} extension rather than the sheet's own {@code
 *     dataValidations}. Excel writes a list there when it points at another sheet, and a mainstream
 *     reader drops the extension — which is where the first template kept the one rule it enforces
 */
public record ListValidation(List<CellRange> ranges, String source, boolean fromExtension) {

    public ListValidation {
        ranges = List.copyOf(ranges);
        Objects.requireNonNull(source, "source");
    }

    /** The rows it covers in one column, when it covers exactly one column; the answer column's shape. */
    public boolean singleColumn() {
        return !ranges.isEmpty()
                && ranges.stream().allMatch(range -> range.width() == 1)
                && ranges.stream().map(range -> range.first().column()).distinct().count() == 1;
    }

    public int cellCount() {
        return ranges.stream().mapToInt(range -> range.width() * range.height()).sum();
    }
}
