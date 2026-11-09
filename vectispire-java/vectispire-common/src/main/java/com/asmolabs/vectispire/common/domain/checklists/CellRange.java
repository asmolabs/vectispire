package com.asmolabs.vectispire.common.domain.checklists;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/** A rectangle of cells, its corners included: a merged cell, a validation's range. */
public record CellRange(CellRef first, CellRef last) {

    public CellRange {
        if (first.column() > last.column() || first.row() > last.row()) {
            CellRef topLeft = new CellRef(Math.min(first.column(), last.column()), Math.min(first.row(), last.row()));
            CellRef bottomRight = new CellRef(Math.max(first.column(), last.column()), Math.max(first.row(), last.row()));
            first = topLeft;
            last = bottomRight;
        }
    }

    /** {@code A1:G1}, or a single cell as a range of one; empty for anything else. */
    public static Optional<CellRange> parse(String reference) {
        if (reference == null) {
            return Optional.empty();
        }
        String[] corners = reference.strip().split(":", -1);
        if (corners.length == 1) {
            return CellRef.parse(corners[0]).map(cell -> new CellRange(cell, cell));
        }
        if (corners.length != 2) {
            return Optional.empty();
        }
        Optional<CellRef> first = CellRef.parse(corners[0]);
        Optional<CellRef> last = CellRef.parse(corners[1]);
        return first.isPresent() && last.isPresent() ? Optional.of(new CellRange(first.get(), last.get())) : Optional.empty();
    }

    /** A space-separated list of ranges, as a validation's {@code sqref} holds them; unreadable ones left out. */
    public static List<CellRange> parseList(String references) {
        List<CellRange> ranges = new ArrayList<>();
        if (references != null) {
            for (String reference : references.strip().split("\\s+")) {
                parse(reference).ifPresent(ranges::add);
            }
        }
        return ranges;
    }

    public boolean contains(CellRef cell) {
        return cell.column() >= first.column() && cell.column() <= last.column()
                && cell.row() >= first.row() && cell.row() <= last.row();
    }

    public int width() {
        return last.column() - first.column() + 1;
    }

    public int height() {
        return last.row() - first.row() + 1;
    }

    @Override
    public String toString() {
        return first.equals(last) ? first.toString() : first + ":" + last;
    }
}
