package com.asmolabs.vectispire.common.domain.checklists;

import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import com.asmolabs.vectispire.common.domain.xml.SafeXml;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Consumer;
import java.util.zip.ZipEntry;
import java.util.zip.ZipException;
import java.util.zip.ZipInputStream;

/**
 * Reads an {@code .xlsx} package into a {@link Workbook}, from its parts, with the JDK alone.
 *
 * <h2>The zip, and its guards</h2>
 *
 * <p>Checked as the entries are read, never from what the archive says of itself — a zip bomb's
 * declared sizes are a lie. At most {@code maxEntries} entries; each inflated to at most {@code
 * maxEntryBytes} and all of them to {@code maxInflatedBytes}, counted as the bytes come out of the
 * inflater; and an entry that inflates more than {@code maxRatio} times its compressed bytes, as the
 * inflater consumed them, is refused once it is past a grace too small to hurt. Every entry is read
 * through that counter, the ones not kept too: skipping an entry inflates it all the same. An
 * archive inside the archive — by its name or by its first four bytes — is refused, not opened; so
 * is a part name the archive holds twice, which two programs would each read a different one of.
 * Nothing is written to disk, so an entry's name is a name and nothing more.
 *
 * <h2>What is refused before a cell is read</h2>
 *
 * <p>A legacy {@code .xls} (and an encrypted {@code .xlsx}, which Office stores in the same
 * compound-file container), an OpenDocument spreadsheet, a binary {@code .xlsb}, a macro-enabled
 * workbook — by the workbook part's content type, a VBA project, or an Excel 4 macro sheet — and a
 * package without a workbook part (decision 0032 §11). Then <b>any relationship whose target is
 * external</b> (§3), in any part: the renderer copies the package into a document the platform
 * signs, and a link that makes the reader's spreadsheet fetch something is not a thing to sign.
 *
 * <h2>The XML</h2>
 *
 * <p>Through {@link SafeXml}, a DOCTYPE refused outright: Office never writes one, so a part carrying
 * one was edited by hand to carry it. One element budget spans every part read.
 */
final class WorkbookReader {

    private static final SafeXml XML = SafeXml.of(SafeXml.Doctype.REFUSED, InvalidTemplateException::new);

    /** Excel's own ceiling on a cell's text; longer was not written by Excel. */
    static final int MAX_CELL_TEXT = 32_767;

    private static final byte[] COMPOUND_FILE = {(byte) 0xD0, (byte) 0xCF, 0x11, (byte) 0xE0, (byte) 0xA1, (byte) 0xB1, 0x1A, (byte) 0xE1};
    private static final Set<String> ARCHIVE_SUFFIXES = Set.of(
            ".zip", ".jar", ".gz", ".tgz", ".tar", ".7z", ".rar", ".xlsx", ".xlsm", ".xlsb", ".xltx", ".xltm", ".docx",
            ".docm", ".pptx", ".pptm", ".ods", ".odt");
    private static final String MAIN_SHEET = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml";
    private static final String MAIN_TEMPLATE = "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml";

    private final Workbook.Limits limits;
    private final SafeXml.Budget budget;

    WorkbookReader(Workbook.Limits limits) {
        this.limits = limits;
        this.budget = new SafeXml.Budget(limits.maxElements(), "The workbook");
    }

    Workbook read(byte[] file, long maxBytes) {
        requireZip(file, maxBytes);
        Map<String, Part> parts = unzip(file);

        Part mimetype = parts.get("mimetype");
        if (mimetype != null && new String(mimetype.bytes(), StandardCharsets.US_ASCII).startsWith("application/vnd.oasis.opendocument")) {
            throw new InvalidTemplateException("This is an OpenDocument spreadsheet (.ods): only an .xlsx workbook is "
                    + "read. Save it as an Excel workbook (.xlsx) and import it again.");
        }
        ContentTypes types = contentTypes(parts);
        for (Part part : parts.values()) {
            String type = types.of(part.name());
            if (part.name().toLowerCase(Locale.ROOT).endsWith("vbaproject.bin") || type.contains("vbaproject")
                    || type.contains("macrosheet")) {
                throw macroEnabled();
            }
        }
        for (Part part : parts.values()) {
            if (part.name().toLowerCase(Locale.ROOT).endsWith(".rels")) {
                relationships(part, parts);
            }
        }

        Relationship main = relationships("", parts).stream()
                .filter(relationship -> relationship.type().endsWith("/officeDocument"))
                .findFirst()
                .orElseThrow(() -> new InvalidTemplateException("The package holds no workbook part: is it an .xlsx?"));
        String workbookType = types.of(main.target());
        if (workbookType.contains("binary")) {
            throw new InvalidTemplateException("This is a binary workbook (.xlsb): only an .xlsx workbook is read.");
        }
        if (workbookType.contains("macroenabled")) {
            throw macroEnabled();
        }
        if (!workbookType.equals(MAIN_SHEET) && !workbookType.equals(MAIN_TEMPLATE)) {
            throw new InvalidTemplateException("The package's main part is not a spreadsheet: is it an .xlsx?");
        }
        Part workbookPart = required(parts, main.target());

        List<SheetEntry> entries = new ArrayList<>();
        Map<String, String> definedNames = new LinkedHashMap<>();
        workbook(workbookPart, entries, definedNames);

        Map<String, Relationship> links = new HashMap<>();
        for (Relationship relationship : relationships(workbookPart.name(), parts)) {
            links.put(relationship.id(), relationship);
        }
        List<String> strings = links.values().stream()
                .filter(relationship -> relationship.type().endsWith("/sharedStrings"))
                .findFirst()
                .map(relationship -> sharedStrings(required(parts, relationship.target())))
                .orElse(List.of());

        List<Sheet> sheets = new ArrayList<>();
        Set<String> names = new HashSet<>();
        int[] cells = {0};
        for (SheetEntry entry : entries) {
            Relationship link = links.get(entry.relationship());
            if (link == null) {
                throw new InvalidTemplateException("Sheet \"" + entry.name() + "\" points at no part of the package.");
            }
            if (!link.type().endsWith("/worksheet")) {
                // A chart sheet holds no cells, and no checklist lives on one.
                continue;
            }
            if (!names.add(entry.name().toLowerCase(Locale.ROOT))) {
                throw new InvalidTemplateException("The workbook names two sheets \"" + entry.name() + "\".");
            }
            sheets.add(worksheet(entry.name(), required(parts, link.target()), strings, cells));
        }
        if (sheets.isEmpty()) {
            throw new InvalidTemplateException("The workbook holds no worksheet.");
        }
        return new Workbook(Digests.sha256Hex(file), sheets, definedNames);
    }

    /**
     * Every entry of the package in the archive's order, under the name the archive gives it, its bytes
     * whole — what the renderer copies (decision 0032 §10). Read through the same guards as {@link
     * #read}: the renderer takes the stored template, which passed them at its import, and holds it to
     * them again rather than trusting a row.
     */
    List<PackageEntry> entries(byte[] file, long maxBytes) {
        requireZip(file, maxBytes);
        List<PackageEntry> entries = new ArrayList<>();
        walk(file, true, (entry, bytes) -> entries.add(new PackageEntry(entry.getName(), bytes, entry.isDirectory(),
                entry.getMethod() == ZipEntry.STORED)));
        return entries;
    }

    /** An entry of a package as the archive holds it; {@code stored} when it was not compressed. */
    record PackageEntry(String name, byte[] bytes, boolean directory, boolean stored) {}

    private static void requireZip(byte[] file, long maxBytes) {
        if (file == null || file.length == 0) {
            throw new InvalidTemplateException("The workbook is empty.");
        }
        if (file.length > maxBytes) {
            throw new InvalidTemplateException("The workbook is larger than the " + maxBytes + " bytes accepted.");
        }
        if (startsWith(file, COMPOUND_FILE)) {
            throw new InvalidTemplateException("This is a legacy .xls workbook, or an encrypted one: only an .xlsx "
                    + "without a password is read. Save it as an Excel workbook (.xlsx) and import it again.");
        }
        if (!startsWith(file, new byte[] {'P', 'K', 3, 4})) {
            throw new InvalidTemplateException("The file is not an .xlsx workbook.");
        }
    }

    private static InvalidTemplateException macroEnabled() {
        return new InvalidTemplateException("This workbook carries macros: a template is read without them. Save it as "
                + "an Excel workbook (.xlsx) and import it again.");
    }

    private record Part(String name, byte[] bytes) {}

    /** The package's entries by lower-cased name: OOXML part names compare without case. */
    private Map<String, Part> unzip(byte[] file) {
        Map<String, Part> parts = new LinkedHashMap<>();
        walk(file, false, (entry, bytes) -> {
            if (!entry.isDirectory()) {
                String key = normalizedName(BoundedText.clip(entry.getName(), 200));
                parts.put(key, new Part(key, bytes));
            }
        });
        return parts;
    }

    private interface EntrySink {
        void accept(ZipEntry entry, byte[] bytes);
    }

    /**
     * Walks the archive through the guards, handing each entry on — its bytes when it is kept: every
     * entry with {@code keepAll}, only the parts the reader parses otherwise.
     */
    private void walk(byte[] file, boolean keepAll, EntrySink sink) {
        Set<String> seen = new HashSet<>();
        long[] inflated = {0};
        int entries = 0;
        try (CountingZip zip = new CountingZip(new ByteArrayInputStream(file))) {
            ZipEntry entry;
            while ((entry = zip.getNextEntry()) != null) {
                if (++entries > limits.maxEntries()) {
                    throw new InvalidTemplateException("The workbook's zip holds more than " + limits.maxEntries()
                            + " entries.");
                }
                String name = BoundedText.clip(entry.getName(), 200);
                String key = normalizedName(name);
                if (!seen.add(key)) {
                    throw new InvalidTemplateException("The workbook's zip holds " + name + " twice; two programs "
                            + "could each read a different one.");
                }
                if (ARCHIVE_SUFFIXES.stream().anyMatch(key::endsWith)) {
                    throw nested(name);
                }
                if (entry.isDirectory()) {
                    sink.accept(entry, new byte[0]);
                    continue;
                }
                boolean keep = keepAll || key.endsWith(".xml") || key.endsWith(".rels") || key.equals("mimetype");
                sink.accept(entry, drain(zip, entry, name, keep, inflated));
            }
        } catch (ZipException malformed) {
            throw new InvalidTemplateException("The workbook is not a readable zip archive.");
        } catch (IOException unreadable) {
            throw new InvalidTemplateException("The workbook's zip could not be read to its end.");
        }
        if (entries == 0) {
            throw new InvalidTemplateException("The workbook is an empty zip archive.");
        }
    }

    /**
     * One entry inflated through the counters, kept or discarded. Returns the bytes when kept, and
     * only the head it sniffed otherwise — nobody reads a discarded part.
     */
    private byte[] drain(CountingZip zip, ZipEntry entry, String name, boolean keep, long[] inflated) throws IOException {
        ByteArrayOutputStream kept = new ByteArrayOutputStream();
        byte[] head = new byte[4];
        int headLength = 0;
        long read = 0;
        byte[] buffer = new byte[8192];
        int n;
        while ((n = zip.read(buffer, 0, buffer.length)) > 0) {
            for (int i = 0; i < n && headLength < head.length; i++) {
                head[headLength++] = buffer[i];
            }
            read += n;
            inflated[0] += n;
            if (read > limits.maxEntryBytes()) {
                throw new InvalidTemplateException("Entry " + name + " inflates past " + limits.maxEntryBytes() + " bytes.");
            }
            if (inflated[0] > limits.maxInflatedBytes()) {
                throw new InvalidTemplateException("The workbook inflates past " + limits.maxInflatedBytes() + " bytes.");
            }
            if (entry.getMethod() == ZipEntry.DEFLATED && read > limits.ratioGraceBytes()
                    && read > (long) limits.maxRatio() * Math.max(1, zip.compressedRead())) {
                throw new InvalidTemplateException("Entry " + name + " inflates more than " + limits.maxRatio()
                        + " times its compressed size, as a zip bomb does.");
            }
            if (keep) {
                kept.write(buffer, 0, n);
            }
        }
        if (headLength == 4 && head[0] == 'P' && head[1] == 'K' && head[2] == 3 && head[3] == 4) {
            throw nested(name);
        }
        return keep ? kept.toByteArray() : new byte[0];
    }

    private static InvalidTemplateException nested(String name) {
        return new InvalidTemplateException("Entry " + name + " is an archive inside the workbook; nested archives are "
                + "not opened.");
    }

    /**
     * A zip reader that says how many compressed bytes the current entry's inflater has consumed —
     * exact, where counting what the reader pulled from the stream would be ahead by its buffer.
     * {@code getNextEntry} resets the inflater, so the count is the entry's own.
     */
    private static final class CountingZip extends ZipInputStream {
        CountingZip(InputStream input) {
            super(input);
        }

        long compressedRead() {
            return inf.getBytesRead();
        }
    }

    private record ContentTypes(Map<String, String> defaults, Map<String, String> overrides) {
        /** The part's content type, lower-cased; empty when the package states none. */
        String of(String part) {
            String override = overrides.get(part);
            if (override != null) {
                return override;
            }
            int dot = part.lastIndexOf('.');
            return dot < 0 ? "" : defaults.getOrDefault(part.substring(dot + 1), "");
        }
    }

    private ContentTypes contentTypes(Map<String, Part> parts) {
        Part part = parts.get("[content_types].xml");
        if (part == null) {
            throw new InvalidTemplateException("The package states no content types: it is not an Office Open XML "
                    + "workbook.");
        }
        Map<String, String> defaults = new HashMap<>();
        Map<String, String> overrides = new HashMap<>();
        parse(part, element -> {
            String type = element.attribute("ContentType");
            if (type == null) {
                return;
            }
            String lower = type.strip().toLowerCase(Locale.ROOT);
            if ("Default".equals(element.name()) && element.attribute("Extension") != null) {
                defaults.put(element.attribute("Extension").strip().toLowerCase(Locale.ROOT), lower);
            } else if ("Override".equals(element.name()) && element.attribute("PartName") != null) {
                overrides.put(normalizedName(element.attribute("PartName")), lower);
            }
        });
        return new ContentTypes(defaults, overrides);
    }

    private record Relationship(String id, String type, String target) {}

    /** The relationships of a part — {@code ""} for the package's own — their targets resolved to part names. */
    private List<Relationship> relationships(String source, Map<String, Part> parts) {
        Part part = parts.get(relationshipsOf(source));
        if (part == null) {
            if (source.isEmpty()) {
                throw new InvalidTemplateException("The package holds no relationships part: it is not an .xlsx "
                        + "workbook.");
            }
            return List.of();
        }
        return relationships(part, parts);
    }

    private List<Relationship> relationships(Part part, Map<String, Part> parts) {
        String owner = ownerOf(part.name());
        List<Relationship> found = new ArrayList<>();
        parse(part, element -> {
            if (!"Relationship".equals(element.name())) {
                return;
            }
            String target = element.attribute("Target");
            if ("external".equalsIgnoreCase(String.valueOf(element.attribute("TargetMode")).strip())) {
                throw new InvalidTemplateException("Part " + part.name() + " points outside the package, at \""
                        + BoundedText.clip(String.valueOf(target), 120) + "\"; a template with an external link is "
                        + "not imported, because the document rendered from it is signed.");
            }
            if (target != null && element.attribute("Type") != null) {
                found.add(new Relationship(String.valueOf(element.attribute("Id")), element.attribute("Type").strip(),
                        resolve(owner, target.strip())));
            }
        });
        return found;
    }

    private record SheetEntry(String name, String relationship) {}

    private void workbook(Part part, List<SheetEntry> sheets, Map<String, String> definedNames) {
        String[] name = {null};
        StringBuilder formula = new StringBuilder();
        read(part, new SafeXml.Handler() {
            @Override
            public void start(SafeXml.Element element) {
                switch (element.name()) {
                    case "sheet" -> {
                        String sheet = element.attribute("name");
                        String id = element.attribute("id");
                        if (sheet == null || id == null) {
                            throw new InvalidTemplateException("The workbook lists a sheet without a name or a part.");
                        }
                        if (sheets.size() == limits.maxSheets()) {
                            throw new InvalidTemplateException("The workbook holds more than " + limits.maxSheets()
                                    + " sheets.");
                        }
                        sheets.add(new SheetEntry(sheet, id));
                    }
                    case "definedName" -> {
                        // A name scoped to one sheet means something else on every other: only the
                        // workbook's own are read, and a list naming a local one is left for the importer.
                        name[0] = element.attribute("localSheetId") == null ? element.attribute("name") : null;
                        formula.setLength(0);
                    }
                    default -> {
                        // bookViews, calcPr, fileVersion: nothing a checklist is read from.
                    }
                }
            }

            @Override
            public void text(String characters, int depth) {
                if (name[0] != null) {
                    append(formula, characters, "A defined name");
                }
            }

            @Override
            public void end(String element, int depth) {
                if ("definedName".equals(element) && name[0] != null) {
                    definedNames.put(name[0], formula.toString().strip());
                    name[0] = null;
                }
            }
        });
    }

    private List<String> sharedStrings(Part part) {
        List<String> strings = new ArrayList<>();
        Deque<String> open = new ArrayDeque<>();
        StringBuilder current = new StringBuilder();
        read(part, new SafeXml.Handler() {
            @Override
            public void start(SafeXml.Element element) {
                open.push(element.name());
                if ("si".equals(element.name())) {
                    if (strings.size() == limits.maxSharedStrings()) {
                        throw new InvalidTemplateException("The workbook's shared strings hold more than "
                                + limits.maxSharedStrings() + " entries.");
                    }
                    current.setLength(0);
                }
            }

            @Override
            public void text(String characters, int depth) {
                // The text of a string is its t elements, directly or in a run — never a phonetic
                // reading (rPh), which is a second transcription of the same words.
                if ("t".equals(open.peek()) && !open.contains("rPh")) {
                    append(current, characters, "A shared string");
                }
            }

            @Override
            public void end(String element, int depth) {
                open.pop();
                if ("si".equals(element)) {
                    strings.add(current.toString());
                }
            }
        });
        return strings;
    }

    private Sheet worksheet(String name, Part part, List<String> strings, int[] cellCount) {
        TreeMap<CellRef, CellValue> cells = new TreeMap<>();
        List<CellRange> merged = new ArrayList<>();
        List<ListValidation> validations = new ArrayList<>();
        String what = "Sheet \"" + name + "\"";
        read(part, new SafeXml.Handler() {
            private final Deque<String> open = new ArrayDeque<>();
            private int row;
            private int column;
            private CellRef cell;
            private String type;
            private boolean hasValue;
            private boolean hasFormula;
            private final StringBuilder value = new StringBuilder();
            private final StringBuilder formula = new StringBuilder();
            private final StringBuilder inline = new StringBuilder();
            private String validationType;
            private String validationRanges;
            private final StringBuilder validationFormula = new StringBuilder();
            private final StringBuilder validationSqref = new StringBuilder();

            @Override
            public void start(SafeXml.Element element) {
                String parent = open.peek();
                open.push(element.name());
                switch (element.name()) {
                    case "row" -> {
                        if ("sheetData".equals(parent)) {
                            String r = element.attribute("r");
                            row = r == null ? row + 1 : rowNumber(r, what);
                            column = 0;
                        }
                    }
                    case "c" -> {
                        if ("row".equals(parent)) {
                            String r = element.attribute("r");
                            cell = r == null ? implied(row, column + 1, what) : CellRef.parse(r)
                                    .orElseThrow(() -> new InvalidTemplateException(what + " has a cell at \""
                                            + BoundedText.clip(r, 20) + "\", which is no cell reference."));
                            column = cell.column();
                            type = element.attribute("t");
                            hasValue = false;
                            hasFormula = false;
                            value.setLength(0);
                            formula.setLength(0);
                            inline.setLength(0);
                        }
                    }
                    case "v" -> hasValue |= "c".equals(parent);
                    case "f" -> hasFormula |= "c".equals(parent);
                    case "mergeCell" -> {
                        if ("mergeCells".equals(parent)) {
                            CellRange.parse(element.attribute("ref")).ifPresent(merged::add);
                        }
                    }
                    case "dataValidation" -> {
                        if ("dataValidations".equals(parent)) {
                            validationType = element.attribute("type");
                            // The sheet's own list carries its range as an attribute; the extension's in
                            // an element (xm:sqref) read below.
                            validationRanges = open.contains("ext") ? null : element.attribute("sqref");
                            validationFormula.setLength(0);
                            validationSqref.setLength(0);
                        }
                    }
                    default -> {
                        // Styles, columns, hyperlinks, drawings: the renderer keeps them, nothing reads them.
                    }
                }
            }

            @Override
            public void text(String characters, int depth) {
                String current = open.peek();
                String parent = open.size() > 1 ? parentOf() : "";
                if (cell != null && "v".equals(current) && "c".equals(parent)) {
                    append(value, characters, what + ", cell " + cell + ",");
                } else if (cell != null && "f".equals(current) && "c".equals(parent)) {
                    append(formula, characters, what + ", cell " + cell + ",");
                } else if (cell != null && "t".equals(current) && open.contains("is") && !open.contains("rPh")) {
                    append(inline, characters, what + ", cell " + cell + ",");
                } else if (validationType != null && open.contains("dataValidation")) {
                    if (open.contains("formula1") && ("formula1".equals(current) || "f".equals(current))) {
                        append(validationFormula, characters, what + "'s validation list");
                    } else if ("sqref".equals(current)) {
                        append(validationSqref, characters, what + "'s validation range");
                    }
                }
            }

            private String parentOf() {
                var iterator = open.iterator();
                iterator.next();
                return iterator.next();
            }

            @Override
            public void end(String element, int depth) {
                open.pop();
                if ("c".equals(element) && cell != null && "row".equals(open.peek())) {
                    decode().ifPresent(decoded -> {
                        if (cells.put(cell, decoded) == null && ++cellCount[0] > limits.maxCells()) {
                            throw new InvalidTemplateException("The workbook holds more than " + limits.maxCells()
                                    + " cells with a value.");
                        }
                    });
                    cell = null;
                } else if ("dataValidation".equals(element) && validationType != null && "dataValidations".equals(open.peek())) {
                    if ("list".equals(validationType)) {
                        String ranges = validationRanges != null ? validationRanges : validationSqref.toString();
                        List<CellRange> covered = CellRange.parseList(ranges);
                        if (!covered.isEmpty()) {
                            validations.add(new ListValidation(covered, validationFormula.toString().strip(),
                                    open.contains("ext")));
                        }
                    }
                    validationType = null;
                }
            }

            private Optional<CellValue> decode() {
                String literal = value.toString();
                if (hasFormula) {
                    Optional<String> cached = hasValue ? Optional.of("b".equals(type) ? bool(literal).text() : literal)
                            : Optional.empty();
                    return Optional.of(new CellValue.Formula(formula.toString().strip(), cached));
                }
                String kind = type == null ? "n" : type;
                return switch (kind) {
                    case "s" -> {
                        if (!hasValue) {
                            yield Optional.empty();
                        }
                        int index = sharedIndex(literal.strip());
                        if (index < 0 || index >= strings.size()) {
                            throw new InvalidTemplateException(what + ", cell " + cell + " refers to a shared string the "
                                    + "workbook does not hold.");
                        }
                        yield textValue(strings.get(index));
                    }
                    case "inlineStr" -> textValue(inline.toString());
                    case "str", "d" -> hasValue ? textValue(literal) : Optional.empty();
                    case "b" -> hasValue ? Optional.of(bool(literal)) : Optional.empty();
                    case "e" -> hasValue ? Optional.of(new CellValue.Error(literal.strip())) : Optional.empty();
                    default -> literal.isBlank() ? Optional.empty() : Optional.of(new CellValue.Number(literal.strip()));
                };
            }
        });
        return new Sheet(name, cells, merged, validations);
    }

    private static Optional<CellValue> textValue(String text) {
        return text.isEmpty() ? Optional.empty() : Optional.of(new CellValue.Text(text));
    }

    private static CellValue.Bool bool(String literal) {
        return new CellValue.Bool("1".equals(literal.strip()) || "true".equalsIgnoreCase(literal.strip()));
    }

    private static int sharedIndex(String literal) {
        if (literal.isEmpty() || literal.length() > 9 || !literal.chars().allMatch(c -> c >= '0' && c <= '9')) {
            return -1;
        }
        return Integer.parseInt(literal);
    }

    private static int rowNumber(String literal, String what) {
        String digits = literal.strip();
        if (digits.isEmpty() || digits.length() > 7 || !digits.chars().allMatch(c -> c >= '0' && c <= '9')
                || Integer.parseInt(digits) < 1 || Integer.parseInt(digits) > CellRef.MAX_ROW) {
            throw new InvalidTemplateException(what + " numbers a row \"" + BoundedText.clip(digits, 20) + "\".");
        }
        return Integer.parseInt(digits);
    }

    /** A cell the file places by its order alone, which the format allows. */
    private static CellRef implied(int row, int column, String what) {
        if (row < 1 || column > CellRef.MAX_COLUMN) {
            throw new InvalidTemplateException(what + " has a cell outside any row.");
        }
        return new CellRef(column, row);
    }

    private static void append(StringBuilder into, String characters, String what) {
        if (into.length() + characters.length() > MAX_CELL_TEXT) {
            throw new InvalidTemplateException(what + " holds more than " + MAX_CELL_TEXT + " characters, which is more "
                    + "than a spreadsheet cell holds.");
        }
        into.append(characters);
    }

    private void parse(Part part, Consumer<SafeXml.Element> starts) {
        read(part, starts::accept);
    }

    private void read(Part part, SafeXml.Handler handler) {
        XML.read(new ByteArrayInputStream(part.bytes()), "Part " + part.name(), budget, handler);
    }

    private static Part required(Map<String, Part> parts, String name) {
        Part part = parts.get(name);
        if (part == null) {
            throw new InvalidTemplateException("The workbook refers to part " + BoundedText.clip(name, 120)
                    + ", which the package does not hold.");
        }
        return part;
    }

    private static boolean startsWith(byte[] bytes, byte[] prefix) {
        if (bytes.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (bytes[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }

    /** A part name as the package's index keys it: no leading slash, percent-escapes decoded, lower case. */
    static String normalizedName(String name) {
        String stripped = name.strip();
        while (stripped.startsWith("/")) {
            stripped = stripped.substring(1);
        }
        return percentDecoded(stripped).toLowerCase(Locale.ROOT);
    }

    static String relationshipsOf(String part) {
        int slash = part.lastIndexOf('/');
        return part.substring(0, slash + 1) + "_rels/" + part.substring(slash + 1) + ".rels";
    }

    /** The part a relationships part describes the links of: {@code xl/_rels/workbook.xml.rels} → {@code xl/workbook.xml}. */
    private static String ownerOf(String relationshipsPart) {
        String withoutSuffix = relationshipsPart.endsWith(".rels")
                ? relationshipsPart.substring(0, relationshipsPart.length() - ".rels".length())
                : relationshipsPart;
        return withoutSuffix.replaceFirst("(^|/)_rels/", "$1");
    }

    /** A relationship's target, relative to its source part's folder unless it starts at the root. */
    static String resolve(String source, String target) {
        String path = target.startsWith("/") ? target : source.substring(0, source.lastIndexOf('/') + 1) + target;
        Deque<String> segments = new ArrayDeque<>();
        for (String segment : path.split("/")) {
            if (segment.isEmpty() || segment.equals(".")) {
                continue;
            }
            if (segment.equals("..")) {
                segments.pollLast();
            } else {
                segments.addLast(segment);
            }
        }
        return normalizedName(String.join("/", segments));
    }

    private static String percentDecoded(String name) {
        if (name.indexOf('%') < 0) {
            return name;
        }
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        int i = 0;
        while (i < name.length()) {
            if (name.charAt(i) == '%' && i + 2 < name.length() && hex(name.charAt(i + 1)) >= 0
                    && hex(name.charAt(i + 2)) >= 0) {
                bytes.write(hex(name.charAt(i + 1)) * 16 + hex(name.charAt(i + 2)));
                i += 3;
            } else {
                int codePoint = name.codePointAt(i);
                byte[] encoded = Character.toString(codePoint).getBytes(StandardCharsets.UTF_8);
                bytes.write(encoded, 0, encoded.length);
                i += Character.charCount(codePoint);
            }
        }
        return bytes.toString(StandardCharsets.UTF_8);
    }

    private static int hex(char c) {
        return Character.digit(c, 16);
    }
}
