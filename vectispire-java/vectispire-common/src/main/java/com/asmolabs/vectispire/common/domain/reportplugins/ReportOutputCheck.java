package com.asmolabs.vectispire.common.domain.reportplugins;

import com.asmolabs.vectispire.common.domain.xml.SafeXml;
import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.zip.ZipEntry;

/**
 * A report plugin's output checked on its bytes against the media type its manifest declares, before the platform
 * signs anything (decision 0035 §3). Pure: the bytes in, a verdict out, nothing written anywhere.
 *
 * <h2>A type check, not a malware scan</h2>
 *
 * <p>It establishes that the file is the kind of document declared, and of no kind that runs code on opening: no
 * macro project, no macro-enabled main part, no ActiveX, no OpenDocument Basic or script library, no relationship
 * that makes the reader's program fetch something other than a link somebody clicks. It cannot establish that a
 * PDF carries no JavaScript in a compressed object stream, nor that the rendering is true. What bounds those is
 * the signer every report plugin needs (§2), the governor's review of who may sign (§4), and the download's
 * headers.
 *
 * <h2>Per type</h2>
 *
 * <ul>
 *   <li><b>Office Open XML</b> — {@link GuardedZip}'s guards; {@code [Content_Types].xml} present; the package's
 *       {@code officeDocument} relationship pointing at a part the package holds, of exactly the main content
 *       type the declared type requires (a macro-enabled workbook's main part is another type, so an {@code
 *       .xlsm} renamed is refused here even before its {@code vbaProject.bin} is); no part, default or override
 *       declaring a VBA project, a macro sheet, a macro-enabled type or an ActiveX control, and no part named
 *       {@code vbaProject.bin}; no external relationship but a hyperlink — an attached template fetched from a
 *       server is how a document with no macro of its own runs one.
 *   <li><b>OpenDocument</b> — the guards; the first entry {@code mimetype}, stored, holding exactly the declared
 *       type; no {@code Basic/} or {@code Scripts/} directory.
 *   <li><b>PDF</b> — {@code %PDF-1.} or {@code %PDF-2.} first, {@code %%EOF} within the last kilobyte.
 *   <li><b>CSV and plain text</b> — valid UTF-8 and no NUL byte, as §3 says; and nothing a browser would sniff
 *       as HTML or XML, which §3 does not: HTML is the one type refused outright, and a {@code .csv} holding a
 *       page is that type under another name. The patterns are the WHATWG MIME Sniffing standard's.
 * </ul>
 *
 * <p>Every type: not empty, and within the manifest's ceiling.
 */
public final class ReportOutputCheck {

    /** What the check concluded. */
    public sealed interface Verdict {

        record Accepted() implements Verdict {}

        /** @param why the sentence a run's detail and its audit entry carry */
        record Refused(String why) implements Verdict {}
    }

    /**
     * The zip bounds. The importer's ratio and grace; entries and sizes raised from a template's to a whole
     * document's — a presentation of a hundred slides holds a few hundred parts, and a workbook at the 50 MiB
     * ceiling inflates to several times that. Nothing inflated is kept but the few XML parts read.
     */
    static final GuardedZip.Limits ZIP_LIMITS =
            new GuardedZip.Limits(2_000, 256L * 1024 * 1024, 512L * 1024 * 1024, 100, 100L * 1024);

    /** XML elements across the parts read: content types and relationships only. */
    private static final long MAX_ELEMENTS = 1_000_000;

    private static final byte[] COMPOUND_FILE = {(byte) 0xD0, (byte) 0xCF, 0x11, (byte) 0xE0, (byte) 0xA1, (byte) 0xB1,
            0x1A, (byte) 0xE1};

    /** What, in a declared content type, names code: VBA, Excel 4 macro sheets, macro-enabled parts, ActiveX. */
    private static final List<String> CODE_TYPES = List.of("vbaproject", "macrosheet", "macroenabled", "activex");

    /** The WHATWG "HTML" patterns, each to be followed by a space or {@code >}. */
    private static final List<String> HTML_TAGS = List.of("<!doctype html", "<html", "<head", "<script", "<iframe",
            "<h1", "<div", "<font", "<table", "<a", "<style", "<title", "<b", "<body", "<br", "<p");

    private static final int PDF_TRAILER_WINDOW = 1024;

    private ReportOutputCheck() {}

    /**
     * @param maxBytes the manifest's {@code max_output_bytes}
     */
    public static Verdict check(ReportMediaType type, byte[] output, long maxBytes) {
        return check(type, output, maxBytes, ZIP_LIMITS);
    }

    static Verdict check(ReportMediaType type, byte[] output, long maxBytes, GuardedZip.Limits limits) {
        try {
            if (output == null || output.length == 0) {
                throw new OutputRefused("the file is empty.");
            }
            if (output.length > maxBytes) {
                throw new OutputRefused("the file is " + output.length + " bytes, over the manifest's ceiling of "
                        + maxBytes + ".");
            }
            switch (type) {
                case XLSX -> officeOpenXml(output, limits, "application/vnd.openxmlformats-officedocument."
                        + "spreadsheetml.sheet.main+xml");
                case DOCX -> officeOpenXml(output, limits, "application/vnd.openxmlformats-officedocument."
                        + "wordprocessingml.document.main+xml");
                case PPTX -> officeOpenXml(output, limits, "application/vnd.openxmlformats-officedocument."
                        + "presentationml.presentation.main+xml");
                case ODS, ODT -> openDocument(output, limits, type.wireName());
                case PDF -> pdf(output);
                case CSV, TEXT -> text(output);
            }
            return new Verdict.Accepted();
        } catch (OutputRefused refused) {
            return new Verdict.Refused("The output is not the " + type.wireName() + " its manifest declares: "
                    + refused.getMessage());
        }
    }

    private static void officeOpenXml(byte[] output, GuardedZip.Limits limits, String mainType) {
        if (GuardedZip.startsWith(output, COMPOUND_FILE)) {
            throw new OutputRefused("it is a legacy binary Office file, or an encrypted one.");
        }
        List<GuardedZip.Entry> entries = new GuardedZip(limits).read(output,
                name -> name.equals("[content_types].xml") || name.endsWith(".rels"));
        SafeXml xml = SafeXml.of(SafeXml.Doctype.REFUSED, OutputRefused::new);
        SafeXml.Budget budget = new SafeXml.Budget(MAX_ELEMENTS, "The document");

        Map<String, byte[]> kept = new HashMap<>();
        for (GuardedZip.Entry entry : entries) {
            String part = partName(entry.name());
            if (part.endsWith("vbaproject.bin")) {
                throw new OutputRefused("it carries a VBA project (" + entry.name() + "): a macro-enabled package "
                        + "is refused whatever its extension.");
            }
            if (!entry.directory()) {
                kept.put(part, entry.bytes());
            }
        }

        byte[] contentTypes = kept.get("[content_types].xml");
        if (contentTypes == null) {
            throw new OutputRefused("it states no content types ([Content_Types].xml).");
        }
        Map<String, String> defaults = new HashMap<>();
        Map<String, String> overrides = new HashMap<>();
        xml.read(new ByteArrayInputStream(contentTypes), "[Content_Types].xml", budget, element -> {
            String declared = element.attribute("ContentType");
            if (declared == null) {
                return;
            }
            String lower = declared.strip().toLowerCase(Locale.ROOT);
            for (String code : CODE_TYPES) {
                if (lower.contains(code)) {
                    throw new OutputRefused("it declares the content type " + declared.strip()
                            + ", which carries code: a macro-enabled package is refused whatever its extension.");
                }
            }
            if ("Default".equals(element.name()) && element.attribute("Extension") != null) {
                defaults.put(element.attribute("Extension").strip().toLowerCase(Locale.ROOT), lower);
            } else if ("Override".equals(element.name()) && element.attribute("PartName") != null) {
                overrides.put(partName(element.attribute("PartName")), lower);
            }
        });

        String main = null;
        for (Map.Entry<String, byte[]> part : kept.entrySet()) {
            if (!part.getKey().endsWith(".rels")) {
                continue;
            }
            boolean root = part.getKey().equals("_rels/.rels");
            String source = ownerOf(part.getKey());
            String[] found = {null};
            xml.read(new ByteArrayInputStream(part.getValue()), part.getKey(), budget, element -> {
                if (!"Relationship".equals(element.name())) {
                    return;
                }
                String relationship = String.valueOf(element.attribute("Type")).strip();
                String target = element.attribute("Target");
                if ("external".equalsIgnoreCase(String.valueOf(element.attribute("TargetMode")).strip())) {
                    if (!relationship.endsWith("/hyperlink")) {
                        throw new OutputRefused("part " + part.getKey() + " makes the reader fetch \""
                                + clip(String.valueOf(target)) + "\" (" + relationship + "); a link is the only "
                                + "external relationship a signed document may hold.");
                    }
                    return;
                }
                if (root && relationship.endsWith("/officeDocument") && target != null && found[0] == null) {
                    found[0] = resolve(source, target.strip());
                }
            });
            if (root) {
                main = found[0];
            }
        }
        if (main == null) {
            throw new OutputRefused("its package names no main part (no officeDocument relationship in _rels/.rels).");
        }
        if (!kept.containsKey(main)) {
            throw new OutputRefused("its main part " + clip(main) + " is not in the package.");
        }
        String type = overrides.get(main);
        if (type == null) {
            int dot = main.lastIndexOf('.');
            type = dot < 0 ? "" : defaults.getOrDefault(main.substring(dot + 1), "");
        }
        if (!type.equals(mainType)) {
            throw new OutputRefused("its main part is of type \"" + clip(type) + "\", where this type's is \""
                    + mainType + "\".");
        }
    }

    private static void openDocument(byte[] output, GuardedZip.Limits limits, String declared) {
        List<GuardedZip.Entry> entries = new GuardedZip(limits).read(output, name -> name.equals("mimetype"));
        GuardedZip.Entry first = entries.getFirst();
        if (!first.name().equals("mimetype") || first.method() != ZipEntry.STORED) {
            throw new OutputRefused("an OpenDocument package's first entry is \"mimetype\", stored uncompressed.");
        }
        String mimetype = new String(first.bytes(), StandardCharsets.US_ASCII);
        if (!mimetype.equals(declared)) {
            throw new OutputRefused("its mimetype entry says \"" + clip(mimetype) + "\".");
        }
        for (GuardedZip.Entry entry : entries) {
            String name = entry.name().toLowerCase(Locale.ROOT);
            if (name.startsWith("basic/") || name.startsWith("scripts/")) {
                throw new OutputRefused("it carries a macro or script library (" + clip(entry.name()) + ").");
            }
        }
    }

    private static void pdf(byte[] output) {
        String head = new String(output, 0, Math.min(output.length, 7), StandardCharsets.ISO_8859_1);
        if (!head.equals("%PDF-1.") && !head.equals("%PDF-2.")) {
            throw new OutputRefused("a PDF starts with %PDF-1. or %PDF-2.");
        }
        int from = Math.max(0, output.length - PDF_TRAILER_WINDOW);
        String tail = new String(output, from, output.length - from, StandardCharsets.ISO_8859_1);
        if (!tail.contains("%%EOF")) {
            throw new OutputRefused("a PDF ends with %%EOF within its last " + PDF_TRAILER_WINDOW + " bytes; this one "
                    + "does not, so it was cut short or something follows it.");
        }
    }

    private static void text(byte[] output) {
        for (int i = 0; i < output.length; i++) {
            if (output[i] == 0) {
                throw new OutputRefused("it holds a NUL byte at offset " + i + ".");
            }
        }
        String decoded;
        try {
            decoded = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(output))
                    .toString();
        } catch (CharacterCodingException invalid) {
            throw new OutputRefused("it is not valid UTF-8.");
        }
        sniffedAsMarkup(decoded).ifPresent(pattern -> {
            throw new OutputRefused("it opens with " + pattern + ", which a browser reads as HTML or XML; HTML is not "
                    + "a type a report plugin may produce.");
        });
    }

    /** The WHATWG sniffing patterns a text would match, after a byte order mark and leading whitespace. */
    static Optional<String> sniffedAsMarkup(String text) {
        int start = text.startsWith("﻿") ? 1 : 0;
        while (start < text.length() && "\t\n\f\r ".indexOf(text.charAt(start)) >= 0) {
            start++;
        }
        String head = text.substring(start, Math.min(text.length(), start + 16)).toLowerCase(Locale.ROOT);
        if (head.startsWith("<!--")) {
            return Optional.of("\"<!--\"");
        }
        if (head.startsWith("<?xml")) {
            return Optional.of("\"<?xml\"");
        }
        for (String tag : HTML_TAGS) {
            if (head.startsWith(tag) && head.length() > tag.length()
                    && (head.charAt(tag.length()) == ' ' || head.charAt(tag.length()) == '>')) {
                return Optional.of("\"" + text.substring(start, start + tag.length()) + "\"");
            }
        }
        return Optional.empty();
    }

    /** A part name as the package compares it: no leading slash, without case. */
    private static String partName(String name) {
        String stripped = name.startsWith("/") ? name.substring(1) : name;
        return stripped.toLowerCase(Locale.ROOT);
    }

    /** {@code word/_rels/document.xml.rels} speaks for {@code word/document.xml}; {@code _rels/.rels} for the package. */
    private static String ownerOf(String relationshipsPart) {
        String withoutSuffix = relationshipsPart.substring(0, relationshipsPart.length() - ".rels".length());
        return withoutSuffix.replaceFirst("(^|/)_rels/", "$1");
    }

    /** A relationship's target as a part name: relative to its source's folder unless it starts at the root. */
    private static String resolve(String source, String target) {
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
        return String.join("/", segments).toLowerCase(Locale.ROOT);
    }

    private static String clip(String text) {
        return text.length() <= 120 ? text : text.substring(0, 119) + "…";
    }
}
