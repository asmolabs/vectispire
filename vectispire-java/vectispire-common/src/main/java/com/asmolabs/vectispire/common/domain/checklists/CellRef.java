package com.asmolabs.vectispire.common.domain.checklists;

import java.util.Comparator;
import java.util.Optional;

/**
 * A cell of a sheet, by column and row, both counted from 1 — {@code B12} is column 2, row 12.
 *
 * <p>Ordered row by row, then left to right: the order a sheet is read in, and the order a
 * worksheet part must list its cells in.
 */
public record CellRef(int column, int row) implements Comparable<CellRef> {

    /** The grid of the file format itself: column {@code XFD}, row 1,048,576. */
    public static final int MAX_COLUMN = 16_384;
    public static final int MAX_ROW = 1_048_576;

    private static final Comparator<CellRef> ORDER = Comparator.comparingInt(CellRef::row).thenComparingInt(CellRef::column);

    public CellRef {
        if (column < 1 || column > MAX_COLUMN || row < 1 || row > MAX_ROW) {
            throw new InvalidTemplateException("Column " + column + ", row " + row + " is outside a sheet.");
        }
    }

    /** {@code B12}, {@code $B$12}; empty for anything else, a whole column or row included. */
    public static Optional<CellRef> parse(String reference) {
        if (reference == null) {
            return Optional.empty();
        }
        String text = reference.strip().replace("$", "");
        int split = 0;
        while (split < text.length() && isLetter(text.charAt(split))) {
            split++;
        }
        if (split == 0 || split > 3 || split == text.length() || text.length() - split > 7) {
            return Optional.empty();
        }
        int row = 0;
        for (int i = split; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c < '0' || c > '9') {
                return Optional.empty();
            }
            row = row * 10 + (c - '0');
        }
        int column = columnIndex(text.substring(0, split));
        if (row < 1 || row > MAX_ROW || column > MAX_COLUMN) {
            return Optional.empty();
        }
        return Optional.of(new CellRef(column, row));
    }

    /** A column's letters as a person types them ({@code "f"} or {@code "F"}); empty for anything else. */
    public static Optional<Integer> column(String letters) {
        String text = letters == null ? "" : letters.strip();
        if (text.isEmpty() || text.length() > 3 || !text.chars().allMatch(c -> isLetter((char) c))) {
            return Optional.empty();
        }
        int column = columnIndex(text);
        return column <= MAX_COLUMN ? Optional.of(column) : Optional.empty();
    }

    public static String letters(int column) {
        StringBuilder letters = new StringBuilder();
        for (int n = column; n > 0; n = (n - 1) / 26) {
            letters.insert(0, (char) ('A' + (n - 1) % 26));
        }
        return letters.toString();
    }

    public String columnLetters() {
        return letters(column);
    }

    @Override
    public int compareTo(CellRef other) {
        return ORDER.compare(this, other);
    }

    @Override
    public String toString() {
        return columnLetters() + row;
    }

    private static boolean isLetter(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
    }

    private static int columnIndex(String letters) {
        int column = 0;
        for (int i = 0; i < letters.length(); i++) {
            column = column * 26 + (Character.toUpperCase(letters.charAt(i)) - 'A' + 1);
        }
        return column;
    }
}
