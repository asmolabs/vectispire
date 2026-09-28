package com.asmolabs.vectispire.common.domain.checklists;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * A template workbook as read from its {@code .xlsx}: its worksheets in the workbook's order, and
 * the names it defines.
 *
 * <p>Read by {@link #read}, with the guards {@link Limits} lists, from the package's parts and
 * nothing else — no spreadsheet library (decision 0032 §10). What this model does not carry — the
 * styles, the comments, the drawings, the extensions other than a list validation — is not lost: the
 * renderer copies every part of the source file byte for byte and rewrites only a few cells.
 *
 * @param sha256 the SHA-256 of the file as received, lowercase hex
 * @param definedNames the workbook-scoped defined names and their formulas, without a leading
 *     {@code =}; a validation list often points at one
 */
public record Workbook(String sha256, List<Sheet> sheets, Map<String, String> definedNames) {

    public Workbook {
        Objects.requireNonNull(sha256, "sha256");
        sheets = List.copyOf(sheets);
        definedNames = Collections.unmodifiableMap(new LinkedHashMap<>(definedNames));
    }

    /**
     * The ceilings the reader holds a file to, each checked as the bytes are read rather than
     * taken from what the file says of itself.
     *
     * @param maxEntries entries in the zip; a workbook of three sheets has about fifteen
     * @param maxEntryBytes one entry inflated
     * @param maxInflatedBytes every entry inflated, together (decision 0032 §3: 50 MB)
     * @param maxRatio how much larger than its compressed bytes an entry may inflate (§3: 100 to one)
     * @param ratioGraceBytes how much an entry inflates before its ratio is judged: a small part — a
     *     relationship file, an empty sheet — compresses far better than 100 to one and is no bomb
     * @param maxElements XML elements, across every part read
     * @param maxSheets worksheets
     * @param maxCells cells holding a value, across every sheet
     * @param maxSharedStrings entries of the shared strings table
     */
    public record Limits(
            int maxEntries,
            long maxEntryBytes,
            long maxInflatedBytes,
            int maxRatio,
            long ratioGraceBytes,
            long maxElements,
            int maxSheets,
            int maxCells,
            int maxSharedStrings) {

        public static final Limits DEFAULT = new Limits(
                200, 20L * 1024 * 1024, 50L * 1024 * 1024, 100, 100L * 1024, 5_000_000, 64, 1_000_000, 1_000_000);
    }

    /**
     * Reads a workbook under the {@link Limits#DEFAULT default limits}.
     *
     * @param maxBytes the ceiling on the file as received — the route's body limit
     * @throws InvalidTemplateException past a guard, not an {@code .xlsx}, a legacy, OpenDocument,
     *     binary or macro-enabled workbook, an external relationship, a DOCTYPE, malformed XML
     */
    public static Workbook read(byte[] file, long maxBytes) {
        return read(file, maxBytes, Limits.DEFAULT);
    }

    public static Workbook read(byte[] file, long maxBytes, Limits limits) {
        return new WorkbookReader(limits).read(file, maxBytes);
    }

    public Optional<Sheet> sheet(String name) {
        return sheets.stream().filter(sheet -> sheet.name().equals(name)).findFirst();
    }

    /**
     * The values a list validation allows, in the order the list holds them, blanks and repeats left
     * out — what the preview offers the importer to map to yes, no and not applicable.
     *
     * <p>Empty when the list's formula is not one this reads: a literal list, a range on a sheet
     * of this workbook, or a defined name standing for one. A list computed by {@code INDIRECT} or
     * {@code OFFSET} is a formula, and formulas are not evaluated; the importer then types the words.
     *
     * @param on the sheet the validation belongs to, against which a range without a sheet is read
     */
    public List<String> listValues(ListValidation validation, Sheet on) {
        return values(validation.source().strip(), on, 0);
    }

    private List<String> values(String formula, Sheet on, int indirections) {
        String source = formula.startsWith("=") ? formula.substring(1).strip() : formula;
        if (source.length() >= 2 && source.startsWith("\"") && source.endsWith("\"")) {
            Set<String> words = new LinkedHashSet<>();
            for (String word : source.substring(1, source.length() - 1).replace("\"\"", "\"").split(",")) {
                if (!word.isBlank()) {
                    words.add(word.strip());
                }
            }
            return List.copyOf(words);
        }
        String name = definedNames.get(source);
        if (name != null) {
            // A name standing for a name is legal; one standing for itself would never end.
            return indirections < 3 ? values(name, on, indirections + 1) : List.of();
        }
        Sheet target = on;
        String range = source;
        int bang = source.lastIndexOf('!');
        if (bang >= 0) {
            String sheetName = source.substring(0, bang);
            if (sheetName.length() >= 2 && sheetName.startsWith("'") && sheetName.endsWith("'")) {
                sheetName = sheetName.substring(1, sheetName.length() - 1).replace("''", "'");
            }
            Optional<Sheet> named = sheet(sheetName);
            if (named.isEmpty()) {
                return List.of();
            }
            target = named.get();
            range = source.substring(bang + 1);
        }
        Optional<CellRange> cells = CellRange.parse(range);
        if (cells.isEmpty()) {
            return List.of();
        }
        Set<String> words = new LinkedHashSet<>();
        CellRange area = cells.get();
        // Walked over the cells the sheet holds, not over the range's grid: A1:A1048576 is a legal list.
        for (Map.Entry<CellRef, CellValue> cell : target.cells().subMap(area.first(), true, area.last(), true).entrySet()) {
            if (area.contains(cell.getKey()) && !cell.getValue().text().isBlank()) {
                words.add(cell.getValue().text().strip());
            }
        }
        return List.copyOf(words);
    }
}
