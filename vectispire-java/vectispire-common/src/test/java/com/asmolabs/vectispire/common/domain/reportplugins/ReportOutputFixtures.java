package com.asmolabs.vectispire.common.domain.reportplugins;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.SequencedMap;
import java.util.zip.CRC32;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Minimal documents of each type a report plugin may produce, written part by part as Office and LibreOffice
 * write them; the tests build the disguises from their parts.
 */
final class ReportOutputFixtures {

    private ReportOutputFixtures() {}

    static final String XLSX_MAIN = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml";
    static final String XLSM_MAIN = "application/vnd.ms-excel.sheet.macroEnabled.main+xml";
    static final String DOCX_MAIN = "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml";
    static final String PPTX_MAIN = "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml";
    static final String OFFICE_DOCUMENT =
            "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument";

    /** An entry to write: deflated unless {@code stored}. */
    record Part(byte[] bytes, boolean stored) {
        static Part of(String text) {
            return new Part(text.getBytes(StandardCharsets.UTF_8), false);
        }
    }

    static byte[] zip(SequencedMap<String, Part> parts) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
            for (var named : parts.entrySet()) {
                ZipEntry entry = new ZipEntry(named.getKey());
                Part part = named.getValue();
                if (part.stored()) {
                    CRC32 crc = new CRC32();
                    crc.update(part.bytes());
                    entry.setMethod(ZipEntry.STORED);
                    entry.setSize(part.bytes().length);
                    entry.setCompressedSize(part.bytes().length);
                    entry.setCrc(crc.getValue());
                }
                zip.putNextEntry(entry);
                zip.write(part.bytes());
                zip.closeEntry();
            }
        } catch (IOException impossible) {
            throw new UncheckedIOException(impossible);
        }
        return bytes.toByteArray();
    }

    static String contentTypes(String mainPart, String mainType, String... more) {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
                + "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\">"
                + "<Default Extension=\"rels\" ContentType=\"application/vnd.openxmlformats-package.relationships+xml\"/>"
                + "<Default Extension=\"xml\" ContentType=\"application/xml\"/>"
                + "<Override PartName=\"/" + mainPart + "\" ContentType=\"" + mainType + "\"/>"
                + String.join("", more)
                + "</Types>";
    }

    static String relationships(String... relationships) {
        return "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
                + "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">"
                + String.join("", relationships)
                + "</Relationships>";
    }

    static String relationship(String id, String type, String target) {
        return "<Relationship Id=\"" + id + "\" Type=\"" + type + "\" Target=\"" + target + "\"/>";
    }

    /** The parts of a one-sheet workbook Excel opens, the sheet holding one cell; callers add or replace parts. */
    static LinkedHashMap<String, Part> workbookParts(String mainType) {
        LinkedHashMap<String, Part> parts = new LinkedHashMap<>();
        parts.put("[Content_Types].xml", Part.of(contentTypes("xl/workbook.xml", mainType,
                "<Override PartName=\"/xl/worksheets/sheet1.xml\" ContentType=\"application/vnd.openxmlformats-"
                        + "officedocument.spreadsheetml.worksheet+xml\"/>")));
        parts.put("_rels/.rels", Part.of(relationships(relationship("rId1", OFFICE_DOCUMENT, "xl/workbook.xml"))));
        parts.put("xl/workbook.xml", Part.of("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
                + "<workbook xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\" "
                + "xmlns:r=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships\">"
                + "<sheets><sheet name=\"Summary\" sheetId=\"1\" r:id=\"rId1\"/></sheets></workbook>"));
        parts.put("xl/_rels/workbook.xml.rels", Part.of(relationships(relationship("rId1",
                "http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet",
                "worksheets/sheet1.xml"))));
        parts.put("xl/worksheets/sheet1.xml", Part.of("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
                + "<worksheet xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><sheetData>"
                + "<row r=\"1\"><c r=\"A1\" t=\"inlineStr\"><is><t>Checkout</t></is></c></row></sheetData></worksheet>"));
        return parts;
    }

    /** A minimal {@code .xlsx}. */
    static byte[] xlsx() {
        return zip(workbookParts(XLSX_MAIN));
    }

    /** A minimal {@code .docx}: one paragraph. */
    static byte[] docx() {
        LinkedHashMap<String, Part> parts = new LinkedHashMap<>();
        parts.put("[Content_Types].xml", Part.of(contentTypes("word/document.xml", DOCX_MAIN)));
        parts.put("_rels/.rels", Part.of(relationships(relationship("rId1", OFFICE_DOCUMENT, "word/document.xml"))));
        parts.put("word/document.xml", Part.of("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
                + "<w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body>"
                + "<w:p><w:r><w:t>Checkout</w:t></w:r></w:p></w:body></w:document>"));
        return zip(parts);
    }

    /** A {@code .pptx} reduced to its main part: what the check reads of one. */
    static byte[] pptx() {
        LinkedHashMap<String, Part> parts = new LinkedHashMap<>();
        parts.put("[Content_Types].xml", Part.of(contentTypes("ppt/presentation.xml", PPTX_MAIN)));
        parts.put("_rels/.rels", Part.of(relationships(relationship("rId1", OFFICE_DOCUMENT, "/ppt/presentation.xml"))));
        parts.put("ppt/presentation.xml", Part.of("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>"
                + "<p:presentation xmlns:p=\"http://schemas.openxmlformats.org/presentationml/2006/main\"/>"));
        return zip(parts);
    }

    /** The parts of an OpenDocument package, {@code mimetype} first and stored. */
    static LinkedHashMap<String, Part> openDocumentParts(String mimetype) {
        LinkedHashMap<String, Part> parts = new LinkedHashMap<>();
        parts.put("mimetype", new Part(mimetype.getBytes(StandardCharsets.US_ASCII), true));
        parts.put("content.xml", Part.of("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "<office:document-content xmlns:office=\"urn:oasis:names:tc:opendocument:xmlns:office:1.0\" "
                + "office:version=\"1.3\"><office:body/></office:document-content>"));
        parts.put("META-INF/manifest.xml", Part.of("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
                + "<manifest:manifest xmlns:manifest=\"urn:oasis:names:tc:opendocument:xmlns:manifest:1.0\" "
                + "manifest:version=\"1.3\"><manifest:file-entry manifest:full-path=\"/\" manifest:media-type=\""
                + mimetype + "\"/><manifest:file-entry manifest:full-path=\"content.xml\" "
                + "manifest:media-type=\"text/xml\"/></manifest:manifest>"));
        return parts;
    }

    static byte[] ods() {
        return zip(openDocumentParts(ReportMediaType.ODS.wireName()));
    }

    static byte[] odt() {
        return zip(openDocumentParts(ReportMediaType.ODT.wireName()));
    }

    /** A one-page PDF with its cross-reference table, as small as a valid one gets. */
    static byte[] pdf() {
        String[] objects = {
            "<< /Type /Catalog /Pages 2 0 R >>",
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>"
        };
        StringBuilder pdf = new StringBuilder("%PDF-1.7\n");
        int[] offsets = new int[objects.length];
        for (int i = 0; i < objects.length; i++) {
            offsets[i] = pdf.length();
            pdf.append(i + 1).append(" 0 obj\n").append(objects[i]).append("\nendobj\n");
        }
        int xref = pdf.length();
        pdf.append("xref\n0 ").append(objects.length + 1).append("\n0000000000 65535 f \n");
        for (int offset : offsets) {
            pdf.append(String.format("%010d 00000 n \n", offset));
        }
        pdf.append("trailer\n<< /Size ").append(objects.length + 1).append(" /Root 1 0 R >>\nstartxref\n").append(xref)
                .append("\n%%EOF\n");
        return pdf.toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    static byte[] csv() {
        return "target,severity,count\nCheckout,critical,2\nCafé — façade,low,1\n".getBytes(StandardCharsets.UTF_8);
    }

    /** What each type's minimal file is. */
    static Map<ReportMediaType, byte[]> minimal() {
        Map<ReportMediaType, byte[]> files = new LinkedHashMap<>();
        files.put(ReportMediaType.XLSX, xlsx());
        files.put(ReportMediaType.DOCX, docx());
        files.put(ReportMediaType.PPTX, pptx());
        files.put(ReportMediaType.ODS, ods());
        files.put(ReportMediaType.ODT, odt());
        files.put(ReportMediaType.PDF, pdf());
        files.put(ReportMediaType.CSV, csv());
        files.put(ReportMediaType.TEXT, "Checkout: 2 critical.\n".getBytes(StandardCharsets.UTF_8));
        return files;
    }
}
