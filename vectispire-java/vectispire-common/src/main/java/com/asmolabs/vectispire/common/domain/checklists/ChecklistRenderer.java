package com.asmolabs.vectispire.common.domain.checklists;

import com.asmolabs.vectispire.common.domain.checklists.WorkbookReader.PackageEntry;
import com.asmolabs.vectispire.common.domain.crypto.Digests;
import com.asmolabs.vectispire.common.domain.text.BoundedText;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * The organisation's workbook, filled in: the template's own package with a handful of cells written and
 * one sheet added (decision 0032 §10). A pure function — the template's bytes, the layout its importer
 * confirmed, and the statement in; the package's bytes out.
 *
 * <h2>What is written, and what is not</h2>
 *
 * <p><b>Every entry of the package is copied byte for byte</b>, except the checklist sheet's part, whose
 * item rows receive their answer and comment and whose header's value cells receive the product, the
 * author and the date; and, only as far as adding a sheet asks, the workbook part, its relationships and
 * the content types. The validation lists, the Office extensions, the comments, the styles, the other
 * sheets survive because nothing reads them: the one rule the first template enforced lived in an
 * extension a mainstream spreadsheet library announced it would drop.
 *
 * <p>Inside the sheet part, too, only the cells written change: a cell is replaced in the text of the part
 * ({@link XmlCursor}), its style kept, and every other byte stays where it was. Answers, comments and the
 * header's words are <b>inline strings</b>, so the shared-strings table is never touched — rewriting it
 * would renumber every string every other cell points at. The answer is the template's own word
 * ({@link AnswerWords}), the importer's when the template's list lacked one (question 1).
 *
 * <p><b>The date is a value, the sign-off instant</b> (§2) — a number in the workbook's own date system,
 * the cell's style kept so it reads as the template formatted it. A formula there — the first template
 * had {@code TODAY()}, which dated every saved copy to the day somebody last opened it — is removed, and
 * with it the calculation chain, which names the formula cells and which a spreadsheet would otherwise
 * repair on opening. A revision not signed off has no date, and its date cell is left empty rather than
 * holding a formula that says "now".
 *
 * <h2>The added sheet</h2>
 *
 * <p>{@value #EVIDENCE_SHEET}, appended after the template's own (question 12): one row per line — its
 * answer, who gave it and when, the measurement's outcome, the instant it is as of, the summary of its
 * evidence and that evidence's digest, what the answer and the measurement say together ("declared, not
 * measured" where a yes rests on no data, question 4), the proofs' links and digests — then the
 * submitter, the signer and the four-eyes rule that applied (question 2). A revision not signed off opens
 * with {@value #DRAFT_BANNER}, since its figures are this rendering's and nobody has signed them.
 *
 * <h2>The same bytes every time</h2>
 *
 * <p>Entries in their original order, the added one last, each dated {@link DocumentZip#ENTRY_TIME}: a
 * revision renders to the same package, and a document can be told from a second rendering.
 */
public final class ChecklistRenderer {

    public static final String EVIDENCE_SHEET = "Evidence";

    /** The first line of a document nobody has signed: a draft, a submitted or a superseded revision. */
    public static final String DRAFT_BANNER = "Draft — not signed off";

    static final String WORKSHEET_CONTENT_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml";
    static final String MAIN_NAMESPACE = "http://schemas.openxmlformats.org/spreadsheetml/2006/main";
    private static final String RELATIONSHIPS_NAMESPACE = "http://schemas.openxmlformats.org/officeDocument/2006/relationships";

    private static final Pattern ENCODING = Pattern.compile("encoding\\s*=\\s*[\"']([^\"']+)[\"']");
    private static final byte[] UTF8_BOM = {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};

    private ChecklistRenderer() {}

    /** The words a {@linkplain #trial trial} writes: never seen, but the length of real ones. */
    static final String TRIAL_TEXT = "Trial rendering";

    /**
     * Fills the workbook in as a sign-off would, with placeholder answers — every line answered, commented,
     * the header dated — through {@link #render} itself, and returns what it produced, which nobody keeps.
     *
     * <p>Why at publication: a template the renderer cannot write into used to be found at the first
     * sign-off, by which time a project had answered every line of a checklist that could never be signed
     * — and its draft could not even be exported. Every cell a sign-off writes is written here (the
     * renderer writes the answer and comment cells of every line and every header cell, whatever they
     * receive), so a refusal the sign-off would meet is met here, in the same code, rather than predicted
     * by a second reading of the workbook that could drift from it.
     *
     * <p>Pure computation: no row, no signature, no audit entry — the caller holds no key to give it.
     *
     * @param items the version's lines, as its layout read them: their rows are where the answers go
     * @throws InvalidTemplateException as {@link #render} does, {@link WrittenFormulaException} included
     */
    public static byte[] trial(byte[] template, ChecklistLayout layout, List<ChecklistItem> items) {
        Objects.requireNonNull(template, "template");
        Objects.requireNonNull(layout, "layout");
        Instant at = DocumentZip.ENTRY_TIME.toInstant(ZoneOffset.UTC);
        ChecklistAnswer given = ChecklistAnswer.YES;
        List<ChecklistStatement.Line> lines = new ArrayList<>();
        for (ChecklistItem item : items) {
            ChecklistStatement.Answer answer = new ChecklistStatement.Answer(item.position(), given.wireName(),
                    layout.answers().written(given), TRIAL_TEXT, TRIAL_TEXT, AnswerAuthor.PERSON.wireName(), at, null, null, null,
                    false, false);
            lines.add(new ChecklistStatement.Line(item.position(), item.key().value(), item.position(), item.row(),
                    item.domain(), item.objective(), item.control(), item.contact(), item.kpi(), item.contentDigest(),
                    item.evidence().kind().wireName(), item.evidence().validityMonths().orElse(null), answer,
                    List.of(answer), null, Reconciliation.NOT_MEASURED_HERE.wireName(), List.of()));
        }
        ChecklistStatement.Act act = new ChecklistStatement.Act(TRIAL_TEXT, at);
        ChecklistStatement statement = new ChecklistStatement(ChecklistStatement.FORM, "signed_off", true,
                new ChecklistStatement.Project(0, TRIAL_TEXT), 1,
                new ChecklistStatement.Template(TRIAL_TEXT, TRIAL_TEXT, 1, null, Digests.sha256Hex(template)),
                new ChecklistStatement.Header(TRIAL_TEXT, TRIAL_TEXT, at), act, act, act, false, null, at, lines);
        return render(template, layout, statement);
    }

    /**
     * Renders the filled workbook.
     *
     * @param template the version's source file, as imported
     * @param layout the version's confirmed layout: the only thing read to know where to write
     * @throws IllegalStateException when the template does not hash to the statement's source SHA-256, or a
     *     line names a row outside the layout's items — the rows this was given do not belong together
     * @throws InvalidTemplateException past the reader's guards
     * @throws WrittenFormulaException a cell the renderer cannot replace without breaking others: the master
     *     of a formula shared with other cells, or an array formula spanning several — every one named
     */
    public static byte[] render(byte[] template, ChecklistLayout layout, ChecklistStatement statement) {
        Objects.requireNonNull(template, "template");
        Objects.requireNonNull(layout, "layout");
        Objects.requireNonNull(statement, "statement");
        if (!Digests.sha256Hex(template).equals(statement.template().sourceSha256())) {
            throw new IllegalStateException("The template's bytes do not hash to the version's source SHA-256: the "
                    + "document would claim to follow a workbook it was not written into.");
        }
        // Read as an import reads it — every guard, every part parsed by the hardened parser — before a
        // byte of it is spliced.
        Workbook workbook = Workbook.read(template, template.length);
        if (workbook.sheet(layout.sheet()).isEmpty()) {
            throw new InvalidTemplateException("The workbook has no sheet \"" + layout.sheet() + "\", which its layout "
                    + "names.");
        }
        Package parts = new Package(new WorkbookReader(Workbook.Limits.DEFAULT).entries(template, template.length));

        String workbookPart = parts.mainPart();
        String workbookRelsPart = WorkbookReader.relationshipsOf(workbookPart);
        WorkbookParts book = WorkbookParts.read(parts.text(workbookPart));
        List<Relationship> links = Relationship.read(parts.text(workbookRelsPart), workbookPart);
        SheetEntry checklistSheet = book.sheets().stream().filter(sheet -> sheet.name().equals(layout.sheet())).findFirst()
                .orElseThrow(() -> new InvalidTemplateException("The workbook part lists no sheet \"" + layout.sheet() + "\"."));
        Relationship sheetLink = links.stream().filter(link -> link.id().equals(checklistSheet.relationship())).findFirst()
                .orElseThrow(() -> new InvalidTemplateException("Sheet \"" + layout.sheet() + "\" points at no part."));
        String sheetPart = sheetLink.target();

        SheetPatch patch = SheetPatch.apply(parts.text(sheetPart), writes(layout, statement, book.date1904()));
        parts.replace(sheetPart, patch.xml());

        String contentTypes = parts.text("[content_types].xml");
        String workbookRels = parts.text(workbookRelsPart);
        if (patch.formulaRemoved()) {
            for (Relationship chain : links.stream().filter(link -> link.type().endsWith("/calcChain")).toList()) {
                parts.drop(chain.target());
                workbookRels = Splice.removeElement(workbookRels, "Relationship", "Id", chain.id());
                contentTypes = Splice.removeOverride(contentTypes, chain.target());
            }
        }

        // The added sheet, beside the template's: its part in the workbook's folder, the next free number.
        String folder = parts.originalName(workbookPart);
        folder = folder.substring(0, folder.lastIndexOf('/') + 1);
        int number = book.sheets().size() + 1;
        while (parts.has(WorkbookReader.normalizedName(folder + "worksheets/sheet" + number + ".xml"))) {
            number++;
        }
        String evidenceFile = "worksheets/sheet" + number + ".xml";
        String evidencePart = folder + evidenceFile;
        String relationshipId = freeId(links);
        String sheetName = freeName(book.sheets());
        String worksheetType = Splice.overrideType(contentTypes, sheetPart).orElse(WORKSHEET_CONTENT_TYPE);

        contentTypes = Splice.insertBeforeEnd(contentTypes, "Types", prefix -> "<" + prefix + "Override PartName=\"/"
                + XmlCursor.escapeAttribute(evidencePart) + "\" ContentType=\"" + XmlCursor.escapeAttribute(worksheetType)
                + "\"/>");
        workbookRels = Splice.insertBeforeEnd(workbookRels, "Relationships", prefix -> "<" + prefix + "Relationship Id=\""
                + relationshipId + "\" Type=\"" + XmlCursor.escapeAttribute(sheetLink.type()) + "\" Target=\""
                + evidenceFile + "\"/>");
        String sheetElement = checklistSheet.tag().prefix() + "sheet";
        String idAttribute = checklistSheet.idAttribute();
        String declaration = checklistSheet.idDeclaration().map(uri -> " xmlns:" + idAttribute.substring(0,
                idAttribute.indexOf(':')) + "=\"" + XmlCursor.escapeAttribute(uri) + "\"").orElse("");
        String bookXml = Splice.insertBeforeEnd(parts.text(workbookPart), "sheets", prefix -> "<" + sheetElement
                + declaration + " name=\"" + XmlCursor.escapeAttribute(sheetName) + "\" sheetId=\"" + book.nextSheetId()
                + "\" " + idAttribute + "=\"" + relationshipId + "\"/>");

        parts.replace("[content_types].xml", contentTypes);
        parts.replace(workbookRelsPart, workbookRels);
        parts.replace(workbookPart, bookXml);
        parts.add(evidencePart, EvidenceSheet.xml(statement, layout, patch.namespace()));
        return parts.write();
    }

    // ------------------------------------------------------------------ the cells

    /** What a cell receives. */
    sealed interface CellWrite {
        record Text(String text) implements CellWrite {}

        record Number(String literal) implements CellWrite {}

        /** Emptied: the cell stays, with its style, and holds nothing. */
        record Blank() implements CellWrite {}
    }

    /** Each cell the statement writes, row by row. */
    private static SortedMap<Integer, SortedMap<Integer, CellWrite>> writes(ChecklistLayout layout,
            ChecklistStatement statement, boolean date1904) {
        SortedMap<Integer, SortedMap<Integer, CellWrite>> rows = new TreeMap<>();
        int answerColumn = layout.column(ChecklistColumn.ANSWER).orElseThrow();
        int commentColumn = layout.column(ChecklistColumn.COMMENT).orElseThrow();
        for (ChecklistStatement.Line line : statement.lines()) {
            if (line.row() < layout.firstItemRow() || line.row() > layout.lastItemRow()) {
                throw new IllegalStateException("Line " + line.position() + " names row " + line.row() + ", outside the "
                        + "layout's items (" + layout.firstItemRow() + " to " + layout.lastItemRow() + ").");
            }
            SortedMap<Integer, CellWrite> cells = rows.computeIfAbsent(line.row(), row -> new TreeMap<>());
            Optional<ChecklistStatement.Answer> answer = Optional.ofNullable(line.answer());
            cells.put(answerColumn, answer.<CellWrite>map(given -> new CellWrite.Text(word(layout.answers(), given)))
                    .orElse(new CellWrite.Blank()));
            cells.put(commentColumn, answer.map(ChecklistStatement.Answer::comment).filter(comment -> !comment.isBlank())
                    .<CellWrite>map(CellWrite.Text::new).orElse(new CellWrite.Blank()));
        }
        layout.header().forEach((field, cell) -> {
            CellWrite write = switch (field) {
                case PRODUCT -> new CellWrite.Text(statement.header().product());
                case AUTHOR -> new CellWrite.Text(statement.header().author());
                case DATE -> Optional.ofNullable(statement.header().date())
                        .<CellWrite>map(date -> new CellWrite.Number(serial(date, date1904)))
                        .orElse(new CellWrite.Blank());
            };
            rows.computeIfAbsent(cell.value().row(), row -> new TreeMap<>()).put(cell.value().column(), write);
        });
        return rows;
    }

    /** The template's word for an answer, as {@link AnswerWords#written} gives it. */
    static String word(AnswerWords words, ChecklistStatement.Answer answer) {
        return words.written(ChecklistAnswer.parse(answer.value()));
    }

    /**
     * An instant as a spreadsheet date: days since the workbook's epoch, the time of day as the fraction,
     * in UTC, to the second. The 1900 system counts from 1899-12-30, which absorbs the leap day 1900 never
     * had — right for every date after February 1900, which a sign-off is.
     */
    static String serial(Instant instant, boolean date1904) {
        LocalDateTime utc = LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
        LocalDate epoch = date1904 ? LocalDate.of(1904, 1, 1) : LocalDate.of(1899, 12, 30);
        long days = ChronoUnit.DAYS.between(epoch, utc.toLocalDate());
        BigDecimal fraction = BigDecimal.valueOf(utc.toLocalTime().toSecondOfDay())
                .divide(BigDecimal.valueOf(86_400), 10, RoundingMode.HALF_EVEN);
        BigDecimal value = BigDecimal.valueOf(days).add(fraction).stripTrailingZeros();
        return value.scale() < 0 ? value.setScale(0).toPlainString() : value.toPlainString();
    }

    private static String freeId(List<Relationship> links) {
        Set<String> taken = links.stream().map(Relationship::id).collect(Collectors.toSet());
        int n = links.size() + 1;
        while (taken.contains("rId" + n)) {
            n++;
        }
        return "rId" + n;
    }

    /** {@value #EVIDENCE_SHEET}, or {@code Evidence (2)} when the template already has a sheet of that name. */
    private static String freeName(List<SheetEntry> sheets) {
        Set<String> taken = sheets.stream().map(sheet -> sheet.name().toLowerCase(Locale.ROOT)).collect(Collectors.toSet());
        String name = EVIDENCE_SHEET;
        for (int n = 2; taken.contains(name.toLowerCase(Locale.ROOT)); n++) {
            name = EVIDENCE_SHEET + " (" + n + ")";
        }
        return name;
    }

    // ------------------------------------------------------------------ the package

    /** The package's entries by normalised name, and what is replaced, dropped and added. */
    private static final class Package {
        private final List<PackageEntry> entries;
        private final Map<String, Integer> index = new HashMap<>();
        private final Map<Integer, byte[]> replaced = new HashMap<>();
        private final Set<Integer> dropped = new HashSet<>();
        private final Map<String, byte[]> added = new LinkedHashMap<>();

        Package(List<PackageEntry> entries) {
            this.entries = entries;
            for (int i = 0; i < entries.size(); i++) {
                if (!entries.get(i).directory()) {
                    index.put(WorkbookReader.normalizedName(entries.get(i).name()), i);
                }
            }
        }

        boolean has(String part) {
            return index.containsKey(part);
        }

        String originalName(String part) {
            return entries.get(required(part)).name();
        }

        String mainPart() {
            return Relationship.read(text("_rels/.rels"), "").stream()
                    .filter(link -> link.type().endsWith("/officeDocument")).findFirst()
                    .map(Relationship::target)
                    .orElseThrow(() -> new InvalidTemplateException("The package holds no workbook part."));
        }

        /**
         * A part's text. UTF-8 only — what Office writes, and what the reader accepted; a part declared in
         * another encoding would be spliced as the wrong characters.
         */
        String text(String part) {
            int at = required(part);
            byte[] bytes = replaced.getOrDefault(at, entries.get(at).bytes());
            int offset = startsWith(bytes, UTF8_BOM) ? UTF8_BOM.length : 0;
            if (bytes.length >= 2 && ((bytes[0] == (byte) 0xFE && bytes[1] == (byte) 0xFF)
                    || (bytes[0] == (byte) 0xFF && bytes[1] == (byte) 0xFE))) {
                throw new InvalidTemplateException("Part " + part + " is written in UTF-16, which the renderer does not "
                        + "write into.");
            }
            String text = new String(bytes, offset, bytes.length - offset, StandardCharsets.UTF_8);
            Matcher declared = ENCODING.matcher(text.substring(0, Math.min(text.length(), 200)));
            if (text.startsWith("<?xml") && declared.find() && !declared.group(1).equalsIgnoreCase("UTF-8")) {
                throw new InvalidTemplateException("Part " + part + " is written in " + BoundedText.clip(declared.group(1), 20)
                        + ", which the renderer does not write into.");
            }
            return text;
        }

        void replace(String part, String text) {
            int at = required(part);
            byte[] encoded = text.getBytes(StandardCharsets.UTF_8);
            if (startsWith(entries.get(at).bytes(), UTF8_BOM)) {
                byte[] withBom = new byte[encoded.length + UTF8_BOM.length];
                System.arraycopy(UTF8_BOM, 0, withBom, 0, UTF8_BOM.length);
                System.arraycopy(encoded, 0, withBom, UTF8_BOM.length, encoded.length);
                encoded = withBom;
            }
            replaced.put(at, encoded);
        }

        void drop(String part) {
            if (has(part)) {
                dropped.add(index.get(part));
            }
        }

        void add(String name, String text) {
            added.put(name, text.getBytes(StandardCharsets.UTF_8));
        }

        byte[] write() {
            LinkedHashMap<String, DocumentZip.Entry> written = new LinkedHashMap<>();
            for (int i = 0; i < entries.size(); i++) {
                if (dropped.contains(i)) {
                    continue;
                }
                PackageEntry entry = entries.get(i);
                written.put(entry.name(), new DocumentZip.Entry(replaced.getOrDefault(i, entry.bytes()), entry.stored(),
                        entry.directory()));
            }
            added.forEach((name, bytes) -> written.put(name, DocumentZip.Entry.of(bytes)));
            return DocumentZip.of(written);
        }

        private int required(String part) {
            Integer at = index.get(part);
            if (at == null) {
                throw new InvalidTemplateException("The workbook refers to part " + BoundedText.clip(part, 120)
                        + ", which the package does not hold.");
            }
            return at;
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
    }

    /** A relationship of a part, its target resolved to a part name. */
    private record Relationship(String id, String type, String target) {

        static List<Relationship> read(String xml, String source) {
            List<Relationship> found = new ArrayList<>();
            XmlCursor cursor = new XmlCursor(xml);
            for (XmlCursor.Tag tag = cursor.next(); tag != null; tag = cursor.next()) {
                if (tag.opens() && tag.local().equals("Relationship")) {
                    Optional<String> target = tag.attribute("Target");
                    Optional<String> type = tag.attribute("Type");
                    if (target.isPresent() && type.isPresent()) {
                        found.add(new Relationship(tag.attribute("Id").orElse(""), type.get().strip(),
                                WorkbookReader.resolve(source, target.get().strip())));
                    }
                }
            }
            return found;
        }
    }

    /**
     * A sheet the workbook part lists.
     *
     * @param idAttribute the relationship attribute's qualified name, as the workbook spells it ({@code r:id})
     * @param idDeclaration the namespace of that prefix, when the element declared it itself — the added
     *     sheet then declares it too
     */
    private record SheetEntry(String name, String relationship, String idAttribute, Optional<String> idDeclaration,
            XmlCursor.Tag tag) {}

    private record WorkbookParts(List<SheetEntry> sheets, boolean date1904, int nextSheetId) {

        static WorkbookParts read(String xml) {
            List<SheetEntry> sheets = new ArrayList<>();
            boolean date1904 = false;
            int maxId = 0;
            XmlCursor cursor = new XmlCursor(xml);
            for (XmlCursor.Tag tag = cursor.next(); tag != null; tag = cursor.next()) {
                if (!tag.opens()) {
                    continue;
                }
                if (tag.local().equals("workbookPr")) {
                    String value = tag.attribute("date1904").orElse("0").strip();
                    date1904 = value.equals("1") || value.equalsIgnoreCase("true");
                } else if (tag.local().equals("sheet")) {
                    XmlCursor.Attribute id = tag.attributes().stream()
                            .filter(attribute -> attribute.prefixed() && attribute.local().equals("id")
                                    && !attribute.name().startsWith("xmlns:"))
                            .findFirst()
                            .orElseThrow(() -> new InvalidTemplateException("The workbook lists a sheet without a part."));
                    String prefix = id.name().substring(0, id.name().indexOf(':'));
                    sheets.add(new SheetEntry(tag.attribute("name").orElse(""), id.value(), id.name(),
                            tag.attribute("xmlns:" + prefix), tag));
                    try {
                        maxId = Math.max(maxId, Integer.parseInt(tag.attribute("sheetId").orElse("0").strip()));
                    } catch (NumberFormatException unnumbered) {
                        // The added sheet takes a number past every one that reads as a number.
                    }
                }
            }
            return new WorkbookParts(sheets, date1904, maxId + 1);
        }
    }

    // ------------------------------------------------------------------ splicing the small parts

    /** Edits of the content types, the relationships and the workbook part: one element in, one out. */
    private static final class Splice {

        interface Written {
            String with(String prefix);
        }

        /** {@code element} written just before the end tag of {@code parent}, with the parent's prefix. */
        static String insertBeforeEnd(String xml, String parent, Written element) {
            XmlCursor cursor = new XmlCursor(xml);
            for (XmlCursor.Tag tag = cursor.next(); tag != null; tag = cursor.next()) {
                if (tag.local().equals(parent) && tag.kind() == XmlCursor.Kind.END) {
                    return xml.substring(0, tag.start()) + element.with(tag.prefix()) + xml.substring(tag.start());
                }
                if (tag.local().equals(parent) && tag.kind() == XmlCursor.Kind.EMPTY) {
                    return xml.substring(0, tag.start()) + XmlCursor.rewrite(tag, new LinkedHashMap<>(), Set.of(), true)
                            + element.with(tag.prefix()) + "</" + tag.name() + ">" + xml.substring(tag.end());
                }
            }
            throw new InvalidTemplateException("A part of the workbook has no " + parent + " element to add to.");
        }

        /** Removes the {@code element} whose {@code attribute} is {@code value}, with its content if it has one. */
        static String removeElement(String xml, String element, String attribute, String value) {
            XmlCursor cursor = new XmlCursor(xml);
            for (XmlCursor.Tag tag = cursor.next(); tag != null; tag = cursor.next()) {
                if (tag.opens() && tag.local().equals(element) && tag.attribute(attribute).map(value::equals).orElse(false)) {
                    int end = tag.end();
                    if (tag.kind() == XmlCursor.Kind.START) {
                        for (XmlCursor.Tag inner = cursor.next(); inner != null; inner = cursor.next()) {
                            if (inner.kind() == XmlCursor.Kind.END && inner.local().equals(element)) {
                                end = inner.end();
                                break;
                            }
                        }
                    }
                    return xml.substring(0, tag.start()) + xml.substring(end);
                }
            }
            return xml;
        }

        static String removeOverride(String contentTypes, String part) {
            XmlCursor cursor = new XmlCursor(contentTypes);
            for (XmlCursor.Tag tag = cursor.next(); tag != null; tag = cursor.next()) {
                if (tag.opens() && tag.local().equals("Override")
                        && tag.attribute("PartName").map(name -> WorkbookReader.normalizedName(name).equals(part)).orElse(false)) {
                    return removeElement(contentTypes, "Override", "PartName", tag.attribute("PartName").orElseThrow());
                }
            }
            return contentTypes;
        }

        static Optional<String> overrideType(String contentTypes, String part) {
            XmlCursor cursor = new XmlCursor(contentTypes);
            for (XmlCursor.Tag tag = cursor.next(); tag != null; tag = cursor.next()) {
                if (tag.opens() && tag.local().equals("Override")
                        && tag.attribute("PartName").map(name -> WorkbookReader.normalizedName(name).equals(part)).orElse(false)) {
                    return tag.attribute("ContentType").map(String::strip);
                }
            }
            return Optional.empty();
        }
    }

    // ------------------------------------------------------------------ the checklist sheet

    /**
     * The checklist sheet with its cells written.
     *
     * @param namespace the namespace the sheet's root binds its elements to — the added sheet uses it too
     */
    record SheetPatch(String xml, boolean formulaRemoved, String namespace) {

        static SheetPatch apply(String xml, SortedMap<Integer, SortedMap<Integer, CellWrite>> writes) {
            return new Patcher(xml, writes).run();
        }
    }

    /**
     * Walks the sheet's tags once, copying the text between the places it writes. A row the template does
     * not have is created in row order; a cell likewise in column order; a cell it has is replaced whole,
     * keeping its reference and its style.
     */
    private static final class Patcher {
        private final String xml;
        private final SortedMap<Integer, SortedMap<Integer, CellWrite>> writes;
        private final TreeMap<Integer, SortedMap<Integer, CellWrite>> pending;
        private final XmlCursor cursor;
        private final StringBuilder out = new StringBuilder();
        private int copied;
        private boolean formulaRemoved;
        private final List<WrittenFormulaException.Cell> dependedOn = new ArrayList<>();
        private String prefix = "";
        private String namespace = MAIN_NAMESPACE;

        Patcher(String xml, SortedMap<Integer, SortedMap<Integer, CellWrite>> writes) {
            this.xml = xml;
            this.writes = writes;
            this.pending = new TreeMap<>(writes);
            this.cursor = new XmlCursor(xml);
        }

        SheetPatch run() {
            boolean inSheetData = false;
            boolean seenRoot = false;
            int lastRow = 0;
            for (XmlCursor.Tag tag = cursor.next(); tag != null; tag = cursor.next()) {
                String local = tag.local();
                if (!seenRoot && tag.opens()) {
                    seenRoot = true;
                    String rootPrefix = tag.prefix();
                    String declaration = rootPrefix.isEmpty() ? "xmlns" : "xmlns:" + rootPrefix.substring(0, rootPrefix.length() - 1);
                    namespace = tag.attribute(declaration).orElse(MAIN_NAMESPACE);
                }
                if (!inSheetData) {
                    if (local.equals("dimension") && tag.opens()) {
                        widenDimension(tag);
                    } else if (local.equals("sheetData") && tag.opens()) {
                        prefix = tag.prefix();
                        if (tag.kind() == XmlCursor.Kind.EMPTY) {
                            copyTo(tag.start());
                            out.append(XmlCursor.rewrite(tag, new LinkedHashMap<>(), Set.of(), true));
                            appendRowsBefore(Integer.MAX_VALUE);
                            out.append("</").append(tag.name()).append('>');
                            copied = tag.end();
                        } else {
                            inSheetData = true;
                        }
                    }
                    continue;
                }
                if (local.equals("sheetData") && tag.kind() == XmlCursor.Kind.END) {
                    copyTo(tag.start());
                    appendRowsBefore(Integer.MAX_VALUE);
                    inSheetData = false;
                } else if (local.equals("row") && tag.opens()) {
                    Optional<String> r = tag.attribute("r");
                    int number = r.map(value -> rowNumber(value)).orElse(lastRow + 1);
                    boolean inserted = !pending.headMap(number).isEmpty();
                    if (inserted) {
                        copyTo(tag.start());
                        appendRowsBefore(number);
                    }
                    lastRow = number;
                    SortedMap<Integer, CellWrite> cells = pending.remove(number);
                    // A row placed by its order alone follows the one before it: after a row inserted
                    // before it, it states its number, or it would take the inserted row's.
                    boolean fixNumber = inserted && r.isEmpty();
                    if (cells == null) {
                        if (fixNumber) {
                            retag(tag, Map.of("r", String.valueOf(number)), Set.of(), false);
                        }
                        continue;
                    }
                    editRow(tag, number, cells, fixNumber);
                }
            }
            if (!pending.isEmpty()) {
                throw new InvalidTemplateException("The checklist sheet has no sheetData to write rows "
                        + pending.firstKey() + " to.");
            }
            // Every such cell named at once, after the whole sheet was walked: one refusal per cell would
            // have the person import the workbook again for each.
            if (!dependedOn.isEmpty()) {
                throw new WrittenFormulaException(dependedOn);
            }
            out.append(xml, copied, xml.length());
            return new SheetPatch(out.toString(), formulaRemoved, namespace);
        }

        private void editRow(XmlCursor.Tag row, int number, SortedMap<Integer, CellWrite> cells, boolean fixNumber) {
            Map<String, String> set = new LinkedHashMap<>();
            Set<String> remove = new HashSet<>();
            if (fixNumber) {
                set.put("r", String.valueOf(number));
            }
            // `spans` is an optimisation hint naming the columns a row's cells lie in; a cell written outside
            // it would make the hint a lie, so it goes, as the format allows.
            row.attribute("spans").filter(spans -> !cells.keySet().stream().allMatch(column -> within(spans, column)))
                    .ifPresent(spans -> remove.add("spans"));
            if (row.kind() == XmlCursor.Kind.EMPTY) {
                copyTo(row.start());
                out.append(XmlCursor.rewrite(row, new LinkedHashMap<>(set), remove, true));
                cells.forEach((column, write) -> out.append(cell(new CellRef(column, number), Optional.empty(), write)));
                out.append("</").append(row.name()).append('>');
                copied = row.end();
                return;
            }
            if (!set.isEmpty() || !remove.isEmpty()) {
                retag(row, set, remove, false);
            }
            TreeMap<Integer, CellWrite> remaining = new TreeMap<>(cells);
            int lastColumn = 0;
            for (XmlCursor.Tag tag = cursor.next(); tag != null; tag = cursor.next()) {
                if (tag.local().equals("row") && tag.kind() == XmlCursor.Kind.END) {
                    copyTo(tag.start());
                    remaining.forEach((column, write) -> out.append(cell(new CellRef(column, number), Optional.empty(), write)));
                    return;
                }
                if (!tag.local().equals("c") || !tag.opens()) {
                    continue;
                }
                Optional<String> r = tag.attribute("r");
                int column = r.flatMap(CellRef::parse).map(CellRef::column).orElse(lastColumn + 1);
                boolean inserted = !remaining.headMap(column).isEmpty();
                if (inserted) {
                    copyTo(tag.start());
                    remaining.headMap(column).forEach((before, write) ->
                            out.append(cell(new CellRef(before, number), Optional.empty(), write)));
                    remaining.headMap(column).clear();
                }
                lastColumn = column;
                CellWrite write = remaining.remove(column);
                if (write != null) {
                    int end = cellEnd(tag, new CellRef(column, number));
                    copyTo(tag.start());
                    out.append(cell(new CellRef(column, number), rawStyle(tag), write));
                    copied = end;
                } else if (inserted && r.isEmpty()) {
                    retag(tag, Map.of("r", new CellRef(column, number).toString()), Set.of(), false);
                }
            }
            throw new InvalidTemplateException("Row " + number + " of the checklist sheet does not end.");
        }

        /** Where a cell's element ends, noting a formula it held and refusing one others depend on. */
        private int cellEnd(XmlCursor.Tag cell, CellRef reference) {
            if (cell.kind() == XmlCursor.Kind.EMPTY) {
                return cell.end();
            }
            for (XmlCursor.Tag tag = cursor.next(); tag != null; tag = cursor.next()) {
                if (tag.local().equals("f") && tag.opens()) {
                    formulaRemoved = true;
                    Optional<String> ref = tag.attribute("ref");
                    String type = tag.attribute("t").orElse("normal");
                    if ((type.equals("shared") || type.equals("array")) && ref.isPresent()
                            && !CellRange.parse(ref.get()).map(range -> range.first().equals(range.last())).orElse(false)) {
                        dependedOn.add(new WrittenFormulaException.Cell(reference.toString(), type,
                                BoundedText.clip(ref.get().strip(), 30)));
                    }
                }
                if (tag.local().equals("c") && tag.kind() == XmlCursor.Kind.END) {
                    return tag.end();
                }
            }
            throw new InvalidTemplateException("Cell " + reference + " of the checklist sheet does not end.");
        }

        private void appendRowsBefore(int limit) {
            SortedMap<Integer, SortedMap<Integer, CellWrite>> before = pending.headMap(limit);
            before.forEach((number, cells) -> {
                out.append('<').append(prefix).append("row r=\"").append(number).append("\">");
                cells.forEach((column, write) -> out.append(cell(new CellRef(column, number), Optional.empty(), write)));
                out.append("</").append(prefix).append("row>");
            });
            before.clear();
        }

        private String cell(CellRef reference, Optional<String> rawStyle, CellWrite write) {
            StringBuilder cell = new StringBuilder("<").append(prefix).append("c r=\"").append(reference).append('"');
            rawStyle.ifPresent(style -> cell.append(" s=\"").append(style).append('"'));
            switch (write) {
                case CellWrite.Text text -> cell.append(" t=\"inlineStr\"><").append(prefix).append("is><").append(prefix)
                        .append("t xml:space=\"preserve\">")
                        .append(XmlCursor.escapeText(BoundedText.clip(text.text(), WorkbookReader.MAX_CELL_TEXT)))
                        .append("</").append(prefix).append("t></").append(prefix).append("is></").append(prefix).append("c>");
                case CellWrite.Number number -> cell.append("><").append(prefix).append("v>").append(number.literal())
                        .append("</").append(prefix).append("v></").append(prefix).append("c>");
                case CellWrite.Blank blank -> cell.append("/>");
            }
            return cell.toString();
        }

        /** The style attribute exactly as written, which the replacement keeps: the cell looks as it did. */
        private static Optional<String> rawStyle(XmlCursor.Tag cell) {
            return cell.attributes().stream().filter(attribute -> attribute.name().equals("s")).findFirst()
                    .map(XmlCursor.Attribute::raw);
        }

        private void widenDimension(XmlCursor.Tag tag) {
            Optional<CellRange> range = tag.attribute("ref").flatMap(CellRange::parse);
            if (range.isEmpty() || writes.isEmpty()) {
                return;
            }
            int firstRow = Math.min(range.get().first().row(), writes.firstKey());
            int lastRow = Math.max(range.get().last().row(), writes.lastKey());
            int firstColumn = range.get().first().column();
            int lastColumn = range.get().last().column();
            for (SortedMap<Integer, CellWrite> cells : writes.values()) {
                firstColumn = Math.min(firstColumn, cells.firstKey());
                lastColumn = Math.max(lastColumn, cells.lastKey());
            }
            CellRef first = new CellRef(firstColumn, firstRow);
            CellRef last = new CellRef(lastColumn, lastRow);
            String widened = first.equals(last) ? first.toString() : first + ":" + last;
            if (!widened.equals(tag.attribute("ref").orElseThrow())) {
                retag(tag, Map.of("ref", widened), Set.of(), false);
            }
        }

        private void retag(XmlCursor.Tag tag, Map<String, String> set, Set<String> remove, boolean open) {
            copyTo(tag.start());
            out.append(XmlCursor.rewrite(tag, new LinkedHashMap<>(set), remove, open));
            copied = tag.end();
        }

        private void copyTo(int offset) {
            out.append(xml, copied, offset);
            copied = offset;
        }

        private static int rowNumber(String value) {
            try {
                return Integer.parseInt(value.strip());
            } catch (NumberFormatException unreadable) {
                throw new InvalidTemplateException("The checklist sheet numbers a row \"" + BoundedText.clip(value, 20)
                        + "\".");
            }
        }

        /** Whether a column lies within a row's {@code spans}, "1:7" or several such, space-separated. */
        private static boolean within(String spans, int column) {
            for (String span : spans.strip().split("\\s+")) {
                String[] bounds = span.split(":");
                try {
                    int from = Integer.parseInt(bounds[0]);
                    int to = Integer.parseInt(bounds[bounds.length - 1]);
                    if (column >= from && column <= to) {
                        return true;
                    }
                } catch (NumberFormatException unreadable) {
                    return false;
                }
            }
            return false;
        }
    }
}
