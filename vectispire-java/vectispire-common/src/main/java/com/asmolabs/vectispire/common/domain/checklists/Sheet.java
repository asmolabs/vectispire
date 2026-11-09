package com.asmolabs.vectispire.common.domain.checklists;

import java.util.Collections;
import java.util.List;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;

/**
 * One worksheet as the reader found it: the cells that hold something, the merged ranges, the list
 * validations. Blank cells are absent — a styled empty cell holds nothing to read.
 */
public record Sheet(String name, NavigableMap<CellRef, CellValue> cells, List<CellRange> merged, List<ListValidation> validations) {

    public Sheet {
        Objects.requireNonNull(name, "name");
        cells = Collections.unmodifiableNavigableMap(new TreeMap<>(cells));
        merged = List.copyOf(merged);
        validations = List.copyOf(validations);
    }

    public Optional<CellValue> value(CellRef cell) {
        return Optional.ofNullable(cells.get(cell));
    }

    /** The cell's text as a reader sees it; the empty string for a blank cell. */
    public String text(CellRef cell) {
        CellValue value = cells.get(cell);
        return value == null ? "" : value.text();
    }

    public boolean blank(CellRef cell) {
        return text(cell).isBlank() && !(cells.get(cell) instanceof CellValue.Formula);
    }

    /** The cells of one row, left to right. */
    public NavigableMap<CellRef, CellValue> row(int row) {
        return cells.subMap(new CellRef(1, row), true, new CellRef(CellRef.MAX_COLUMN, row), true);
    }

    /** The merged range a cell lies in, when it lies in one. */
    public Optional<CellRange> mergedAt(CellRef cell) {
        return merged.stream().filter(range -> range.contains(cell)).findFirst();
    }

    public int lastRow() {
        return cells.isEmpty() ? 0 : cells.lastKey().row();
    }

    /** Its name and size: a sheet's cells are the organisation's text, and have no place in a log line. */
    @Override
    public String toString() {
        return "Sheet[" + name + ", " + cells.size() + " cells]";
    }
}
