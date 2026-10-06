package com.asmolabs.vectispire.common.domain.checklists;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

/**
 * Where the reader thinks the checklist lives in a workbook — to be confirmed or corrected by the
 * importer, never used as it stands (decision 0032 §3, step 1).
 *
 * <h2>From the file's structure, never from its words</h2>
 *
 * <p>Nothing here looks for "Domain", "Réponse" or "Date": a list of expected words would be one
 * organisation's vocabulary built into the product, and the next template would be read wrong in
 * silence. What it reads instead is what any such workbook has:
 *
 * <ol>
 *   <li><b>The answer column</b> is the one a single-column list validation covers — the sheet's own
 *       or the {@code x14} extension's — the widest when there are several. Its values are the
 *       answer words offered for mapping. The sheet it is on is the checklist sheet; without one, the
 *       sheet with the longest run below a header row is.
 *   <li><b>The column header row</b> is the widest row of text cells — three at least — followed
 *       by a run of filled rows, the longest among equals; the run is the item rows. With a
 *       validation, it is a row labelling the answer column, and its run one the validation covers.
 *   <li><b>The columns</b> are the header row's, left to right. Right of the answer, the comment.
 *       Left of it, the grouped ones first — filled on the first item row and blank below somewhere,
 *       as a domain and an objective are written — then the control, the contact and the KPI in the
 *       order they come. The id column is never proposed: whether a column identifies the lines is
 *       the organisation's to say. But one at the left edge — filled on every line, never twice the
 *       same, a grouped column right after it — is stepped over rather than taken for the control:
 *       otherwise it shifted every column after it by one.
 *   <li><b>The header cells</b> are the label-and-value pairs above the header row, a merged title
 *       aside: the date is the one whose value is a formula or a number, the product and the author
 *       the next two in reading order.
 * </ol>
 *
 * <p>Anything it cannot find is left out rather than guessed, and the importer names it.
 */
public record LayoutProposal(
        String sheet,
        Optional<Integer> columnHeaderRow,
        Optional<Integer> firstItemRow,
        Optional<Integer> lastItemRow,
        Map<ChecklistColumn, String> columns,
        Map<HeaderCell.Field, HeaderCell> header,
        List<String> answerValues) {

    /** A header row is at least this many labelled columns; fewer is a label and its value. */
    static final int MIN_HEADER_COLUMNS = 3;

    public LayoutProposal {
        Objects.requireNonNull(sheet, "sheet");
        Map<ChecklistColumn, String> named = new EnumMap<>(ChecklistColumn.class);
        named.putAll(columns);
        columns = Collections.unmodifiableMap(named);
        Map<HeaderCell.Field, HeaderCell> fields = new EnumMap<>(HeaderCell.Field.class);
        fields.putAll(header);
        header = Collections.unmodifiableMap(fields);
        answerValues = List.copyOf(answerValues);
    }

    /**
     * The layout this proposal becomes once the importer has mapped the answer words, when it found
     * everything a layout needs.
     *
     * @throws InvalidTemplateException a required column or the item rows were not found; the
     *     importer names them
     */
    public ChecklistLayout confirm(AnswerWords answers) {
        if (firstItemRow.isEmpty() || lastItemRow.isEmpty()) {
            throw new InvalidTemplateException("No item rows were found on sheet \"" + sheet + "\"; name them.");
        }
        return new ChecklistLayout(sheet, columns, firstItemRow.get(), lastItemRow.get(), header, answers);
    }

    /** Proposes a layout for a workbook, from its structure alone. */
    public static LayoutProposal of(Workbook workbook) {
        Optional<Candidate> validated = workbook.sheets().stream()
                .flatMap(sheet -> sheet.validations().stream()
                        .filter(ListValidation::singleColumn)
                        .map(validation -> new Candidate(sheet, validation)))
                .max(Comparator.comparingInt(candidate -> candidate.validation().cellCount()));

        if (validated.isPresent()) {
            Sheet sheet = validated.get().sheet();
            ListValidation answers = validated.get().validation();
            int answerColumn = answers.ranges().getFirst().first().column();
            Optional<Block> block = bestBlock(sheet, Optional.of(answers), answerColumn);
            return propose(sheet, block, Optional.of(answerColumn), workbook.listValues(answers, sheet));
        }
        Sheet best = workbook.sheets().getFirst();
        Optional<Block> bestBlock = Optional.empty();
        for (Sheet sheet : workbook.sheets()) {
            Optional<Block> block = bestBlock(sheet, Optional.empty(), 0);
            if (block.isPresent() && (bestBlock.isEmpty() || block.get().length() > bestBlock.get().length())) {
                best = sheet;
                bestBlock = block;
            }
        }
        return propose(best, bestBlock, Optional.empty(), List.of());
    }

    private record Candidate(Sheet sheet, ListValidation validation) {}

    /** A column header row, its columns, and the run of filled rows below it. */
    private record Block(int headerRow, List<Integer> columns, int firstRow, int lastRow) {
        int length() {
            return lastRow - firstRow + 1;
        }
    }

    /**
     * The widest labelled row followed by a run of filled rows: a header row labels every column,
     * an item row leaves its answer and comment blank, a line of prose above spans one or two.
     * Among rows equally wide, the longest run; a row inside a run already read is one of its items.
     * With a validation, the header row labels the answer column, which no item row of a template
     * fills, and its run is one the validation covers.
     */
    private static Optional<Block> bestBlock(Sheet sheet, Optional<ListValidation> answers, int answerColumn) {
        Map<Integer, List<Integer>> headings = new TreeMap<>();
        sheet.cells().forEach((cell, value) -> {
            if (value instanceof CellValue.Text text && !text.text().isBlank()) {
                headings.computeIfAbsent(cell.row(), row -> new ArrayList<>()).add(cell.column());
            }
        });
        Map<Integer, List<Integer>> candidates = new TreeMap<>();
        headings.forEach((row, columns) -> {
            boolean labelsAnswer = answers.isEmpty() || columns.contains(answerColumn);
            if (columns.size() >= MIN_HEADER_COLUMNS && labelsAnswer && filled(sheet, row + 1, runColumns(columns, answerColumn))) {
                candidates.put(row, columns);
            }
        });
        int widest = candidates.values().stream().mapToInt(List::size).max().orElse(0);
        Block best = null;
        int readThrough = 0;
        for (Map.Entry<Integer, List<Integer>> candidate : candidates.entrySet()) {
            int row = candidate.getKey();
            if (candidate.getValue().size() < widest || row <= readThrough) {
                continue;
            }
            List<Integer> filledBy = runColumns(candidate.getValue(), answerColumn);
            int last = row + 1;
            while (last < CellRef.MAX_ROW && last - row < ChecklistLayout.MAX_ITEM_ROWS && filled(sheet, last + 1, filledBy)) {
                last++;
            }
            Block block = new Block(row, candidate.getValue(), row + 1, last);
            readThrough = last;
            if (answers.isPresent() && !covers(answers.get(), block)) {
                continue;
            }
            if (best == null || block.length() > best.length()) {
                best = block;
            }
        }
        return Optional.ofNullable(best);
    }

    /** The answer column is blank in a template, so a run is read in the other columns. */
    private static List<Integer> runColumns(List<Integer> headings, int answerColumn) {
        return headings.stream().filter(column -> column != answerColumn).toList();
    }

    private static boolean filled(Sheet sheet, int row, List<Integer> columns) {
        return columns.stream().anyMatch(column -> !sheet.blank(new CellRef(column, row)));
    }

    private static boolean covers(ListValidation validation, Block block) {
        return validation.ranges().stream()
                .anyMatch(range -> range.first().row() <= block.lastRow() && range.last().row() >= block.firstRow());
    }

    private static LayoutProposal propose(Sheet sheet, Optional<Block> found, Optional<Integer> answer, List<String> values) {
        Map<ChecklistColumn, String> columns = new EnumMap<>(ChecklistColumn.class);
        Map<HeaderCell.Field, HeaderCell> header = new EnumMap<>(HeaderCell.Field.class);
        answer.ifPresent(column -> columns.put(ChecklistColumn.ANSWER, CellRef.letters(column)));
        if (found.isEmpty()) {
            return new LayoutProposal(sheet.name(), Optional.empty(), Optional.empty(), Optional.empty(), columns, header,
                    values);
        }
        Block block = found.get();
        List<Integer> left = block.columns().stream().filter(column -> answer.isEmpty() || column < answer.get()).toList();
        answer.flatMap(column -> block.columns().stream().filter(heading -> heading > column).findFirst())
                .ifPresent(comment -> columns.put(ChecklistColumn.COMMENT, CellRef.letters(comment)));

        // A template that adds an identifier column in front of its domain (SEC-01, SEC-02…) read as
        // control = the identifier, contact = the domain, KPI = the objective: nothing grouped could be
        // found at the edge, so the place of every column after it was off by one. Only that shape is
        // stepped over — one column, identifier-like, a grouped one after it — since a template with
        // no domain may well start with its control and have a KPI left blank on some lines.
        int next = left.size() > 1 && identifierLike(sheet, left.get(0), block) && grouped(sheet, left.get(1), block)
                ? 1 : 0;
        ChecklistColumn[] grouped = {ChecklistColumn.DOMAIN, ChecklistColumn.OBJECTIVE};
        int first = next;
        while (next < left.size() && next - first < grouped.length && grouped(sheet, left.get(next), block)) {
            columns.put(grouped[next - first], CellRef.letters(left.get(next)));
            next++;
        }
        for (ChecklistColumn column : new ChecklistColumn[] {ChecklistColumn.CONTROL, ChecklistColumn.CONTACT,
                ChecklistColumn.KPI}) {
            if (next < left.size()) {
                columns.put(column, CellRef.letters(left.get(next++)));
            }
        }
        headerCells(sheet, block.headerRow(), header);
        return new LayoutProposal(sheet.name(), Optional.of(block.headerRow()), Optional.of(block.firstRow()),
                Optional.of(block.lastRow()), columns, header, values);
    }

    /** Written on every item row, and never twice the same: the shape of a line's identifier. */
    private static boolean identifierLike(Sheet sheet, int column, Block block) {
        Set<String> seen = new HashSet<>();
        for (int row = block.firstRow(); row <= block.lastRow(); row++) {
            CellRef cell = new CellRef(column, row);
            if (sheet.blank(cell) || !seen.add(sheet.text(cell))) {
                return false;
            }
        }
        return true;
    }

    /** Written on the first item row, and left blank on some row below: the fill-down shape. */
    private static boolean grouped(Sheet sheet, int column, Block block) {
        if (sheet.blank(new CellRef(column, block.firstRow()))) {
            return false;
        }
        for (int row = block.firstRow() + 1; row <= block.lastRow(); row++) {
            if (sheet.blank(new CellRef(column, row))) {
                return true;
            }
        }
        return false;
    }

    private static void headerCells(Sheet sheet, int headerRow, Map<HeaderCell.Field, HeaderCell> header) {
        List<HeaderCell> pairs = new ArrayList<>();
        List<HeaderCell> dated = new ArrayList<>();
        for (int row = 1; row < headerRow; row++) {
            int skipUntil = 0;
            for (Map.Entry<CellRef, CellValue> entry : sheet.row(row).entrySet()) {
                CellRef label = entry.getKey();
                if (label.column() <= skipUntil || !(entry.getValue() instanceof CellValue.Text text) || text.text().isBlank()) {
                    continue;
                }
                Optional<CellRange> merge = sheet.mergedAt(label);
                if (merge.isPresent() && merge.get().width() >= MIN_HEADER_COLUMNS) {
                    // A title across the sheet is a heading, not a label.
                    continue;
                }
                int valueColumn = merge.map(range -> range.last().column()).orElse(label.column()) + 1;
                if (valueColumn > CellRef.MAX_COLUMN) {
                    continue;
                }
                CellRef value = new CellRef(valueColumn, row);
                HeaderCell pair = new HeaderCell(label, value);
                boolean isDate = sheet.value(value)
                        .map(held -> held instanceof CellValue.Formula || held instanceof CellValue.Number)
                        .orElse(false);
                (isDate ? dated : pairs).add(pair);
                skipUntil = sheet.mergedAt(value).map(range -> range.last().column()).orElse(valueColumn);
            }
        }
        if (!dated.isEmpty()) {
            header.put(HeaderCell.Field.DATE, dated.getFirst());
        }
        HeaderCell.Field[] named = {HeaderCell.Field.PRODUCT, HeaderCell.Field.AUTHOR};
        for (int i = 0; i < named.length && i < pairs.size(); i++) {
            header.put(named[i], pairs.get(i));
        }
    }
}
