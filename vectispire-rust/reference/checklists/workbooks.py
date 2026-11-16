"""Writes reference/checklists/workbooks.json, the cases the checklist workbook is held to: python3 workbooks.py workbooks.json.

The workbooks are generated part by part from invented controls, shaped like XlsxFixture (vectispire-common's tests), then
varied where the reader, the proposal, the version and the renderer decide something: the zip's guards and its layouts
(data descriptors, stored entries, a bomb, a nested archive, a cut archive), the XML (a DOCTYPE, an entity, encodings,
prefixes, bounds), the cells (implied references, types, formulas shared and arrays), the layout's refusals, the
renderer's splices (rows and cells inserted, spans, the dimension, a calculation chain, a 1904 workbook). Each zip is
written here byte by byte, so both sides read the same bytes; nothing depends on Python's zipfile.
"""
import base64
import hashlib
import json
import struct
import sys
import zlib

MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PACKAGE_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
SHEET_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
WORKSHEET_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"
DECL = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'

STRINGS = [
    "Read every line and answer it.", "Release checklist", "Date", "Product", "Author", "Domain", "Objective",
    "Control", "Contact", "KPI", "Answer", "Comment (required when the answer is negative)", "Identity",
    "1. Accounts are personal", "Every account belongs to one named person.", "Security officer",
    "Shared accounts are disabled.", "No shared account in the directory", "2. Sessions expire", "Development lead",
    "Supply chain", "3. Dependencies are known", "Every build publishes an SBOM.", "SBOM on every release", "Done",
    "Not done",
]


def s(ref, index):
    return f'<c r="{ref}" t="s"><v>{index}</v></c>'


def row(number, cells):
    return f'<row r="{number}">{cells}</row>'


def checklist_rows():
    return (row(1, s("A1", 1))
            + '<row r="2">' + s("A2", 2) + '<c r="B2" s="3"><f>TODAY()</f><v>46293</v></c></row>'
            + row(3, s("A3", 3) + '<c r="B3" s="1"/>')
            + row(4, s("A4", 4))
            + row(6, s("A6", 5) + s("B6", 6) + s("C6", 7) + s("D6", 8) + s("E6", 9) + s("F6", 10) + s("G6", 11))
            + row(7, s("A7", 12) + s("B7", 13) + s("C7", 14) + s("D7", 15))
            + row(8, '<c r="A8" s="1"/>' + s("C8", 16) + s("D8", 15) + s("E8", 17))
            + row(9, s("B9", 18) + s("C9", 20) + s("D9", 19))
            + row(10, s("A10", 21) + s("B10", 22) + s("C10", 23) + s("D10", 19) + s("E10", 24))
            + row(11, '<c r="C11" t="inlineStr"><is><t>Critical vulnerabilities are fixed within 30 days &amp; '
                  'tracked.</t></is></c>' + s("D11", 15)))


def shared_strings(strings=STRINGS):
    xml = DECL + f'<sst xmlns="{MAIN}" count="{len(strings) + 1}">'
    for i, text in enumerate(strings):
        if i == 20:
            xml += ('<si><r><rPr><b/></rPr><t>An idle session</t></r><r><t xml:space="preserve"> ends after '
                    'fifteen minutes.</t></r><rPh sb="0" eb="1"><t>PHONETIC</t></rPh></si>')
        xml += f"<si><t>{text}</t></si>"
    return xml + "</sst>"


def sheet(rows, after="", before=""):
    return DECL + f'<worksheet xmlns="{MAIN}" xmlns:r="{REL}">{before}<sheetData>{rows}</sheetData>{after}</worksheet>'


EXTENSION = ('<mergeCells count="1"><mergeCell ref="A1:G1"/></mergeCells><legacyDrawing r:id="rId2"/>'
             '<extLst><ext uri="{CCE6A557-97BC-4b89-ADB6-D9C93CAAB3DF}" '
             'xmlns:x14="http://schemas.microsoft.com/office/spreadsheetml/2009/9/main">'
             '<x14:dataValidations count="1" xmlns:xm="http://schemas.microsoft.com/office/excel/2006/main">'
             '<x14:dataValidation type="list" allowBlank="1" showInputMessage="1" showErrorMessage="1">'
             '<x14:formula1><xm:f>Values!$A$1:$A$2</xm:f></x14:formula1><xm:sqref>F7:F11</xm:sqref>'
             '</x14:dataValidation></x14:dataValidations></ext></extLst>')


def fixture():
    parts = {}
    parts["[Content_Types].xml"] = (
        DECL + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Default Extension="vml" ContentType="application/vnd.openxmlformats-officedocument.vmlDrawing"/>'
        f'<Override PartName="/xl/workbook.xml" ContentType="{SHEET_TYPE}"/>'
        f'<Override PartName="/xl/worksheets/sheet1.xml" ContentType="{WORKSHEET_TYPE}"/>'
        f'<Override PartName="/xl/worksheets/sheet2.xml" ContentType="{WORKSHEET_TYPE}"/>'
        f'<Override PartName="/xl/worksheets/sheet3.xml" ContentType="{WORKSHEET_TYPE}"/>'
        '<Override PartName="/xl/sharedStrings.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>'
        '<Override PartName="/xl/comments1.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.comments+xml"/>'
        '</Types>')
    parts["_rels/.rels"] = (DECL + f'<Relationships xmlns="{PACKAGE_REL}">'
                            f'<Relationship Id="rId1" Type="{REL}/officeDocument" Target="xl/workbook.xml"/>'
                            '</Relationships>')
    parts["xl/workbook.xml"] = (
        DECL + f'<workbook xmlns="{MAIN}" xmlns:r="{REL}"><sheets>'
        '<sheet name="Instructions" sheetId="1" r:id="rId1"/>'
        '<sheet name="Checklist" sheetId="2" r:id="rId2"/>'
        '<sheet name="Values" sheetId="3" r:id="rId3"/>'
        '</sheets><definedNames><definedName name="AnswerWords">Values!$A$1:$A$2</definedName>'
        '<definedName name="_xlnm.Print_Area" localSheetId="1">Checklist!$A$1:$G$11</definedName></definedNames>'
        '<calcPr calcId="191029"/></workbook>')
    parts["xl/_rels/workbook.xml.rels"] = (
        DECL + f'<Relationships xmlns="{PACKAGE_REL}">'
        f'<Relationship Id="rId1" Type="{REL}/worksheet" Target="worksheets/sheet1.xml"/>'
        f'<Relationship Id="rId2" Type="{REL}/worksheet" Target="worksheets/sheet2.xml"/>'
        f'<Relationship Id="rId3" Type="{REL}/worksheet" Target="/xl/worksheets/sheet3.xml"/>'
        f'<Relationship Id="rId4" Type="{REL}/sharedStrings" Target="sharedStrings.xml"/>'
        '</Relationships>')
    parts["xl/sharedStrings.xml"] = shared_strings()
    parts["xl/worksheets/sheet1.xml"] = sheet(row(1, s("A1", 0)))
    parts["xl/worksheets/sheet2.xml"] = sheet(checklist_rows(), EXTENSION)
    parts["xl/worksheets/_rels/sheet2.xml.rels"] = (
        DECL + f'<Relationships xmlns="{PACKAGE_REL}">'
        f'<Relationship Id="rId1" Type="{REL}/comments" Target="../comments1.xml"/>'
        f'<Relationship Id="rId2" Type="{REL}/vmlDrawing" Target="../drawings/vmlDrawing1.vml"/>'
        '</Relationships>')
    parts["xl/comments1.xml"] = (
        DECL + f'<comments xmlns="{MAIN}"><authors><author>Template author</author></authors><commentList>'
        '<comment ref="C11" authorId="0"><text><r><t>Counted from the advisory\'s publication.</t></r></text>'
        '</comment></commentList></comments>')
    parts["xl/drawings/vmlDrawing1.vml"] = '<xml xmlns:v="urn:schemas-microsoft-com:vml"><v:shape/></xml>'
    parts["xl/worksheets/sheet3.xml"] = sheet(row(1, s("A1", 24)) + row(2, s("A2", 25)))
    return parts


# ---------------------------------------------------------------- the zip, written byte by byte


def deflate(data, level=6):
    compressor = zlib.compressobj(level, zlib.DEFLATED, -15)
    return compressor.compress(data) + compressor.flush()


def zip_bytes(entries, central=True):
    """entries: dicts with name, data, and optionally method ("deflate"/"store"/int), descriptor (bool), signed
    (descriptor signature), flag (extra bits), crc, csize, size (overrides), raw_name (bytes), extra (bytes)."""
    out = bytearray()
    directory = bytearray()
    for entry in entries:
        name = entry.get("raw_name") or entry["name"].encode("utf-8")
        data = entry["data"] if isinstance(entry["data"], bytes) else entry["data"].encode("utf-8")
        method = entry.get("method", "deflate")
        method_id = {"deflate": 8, "store": 0}.get(method, method)
        body = deflate(data) if method_id == 8 else data
        crc = entry.get("crc", zlib.crc32(data) & 0xFFFFFFFF)
        csize = entry.get("csize", len(body))
        size = entry.get("size", len(data))
        descriptor = entry.get("descriptor", False)
        flag = (8 if descriptor else 0) | entry.get("flag", 0)
        extra = entry.get("extra", b"")
        offset = len(out)
        header_crc, header_csize, header_size = (0, 0, 0) if descriptor else (crc, csize, size)
        out += struct.pack("<IHHHIIIIHH", 0x04034B50, 20, flag, method_id, 0x00410000, header_crc, header_csize,
                           header_size, len(name), len(extra))
        out += name + extra + body
        if descriptor:
            if entry.get("signed", True):
                out += struct.pack("<I", 0x08074B50)
            out += struct.pack("<III", crc, csize, size)
        directory += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, flag, method_id, 0, 0x0041, crc, csize, size,
                                 len(name), 0, 0, 0, 0, 0, offset)
        directory += name
    if central:
        start = len(out)
        out += directory
        out += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries), len(entries), len(directory), start, 0)
    return bytes(out)


def package(parts, **options):
    """A workbook from its parts, each deflated with a data descriptor unless options say otherwise."""
    method = options.get("method", "deflate")
    descriptor = options.get("descriptor", True)
    return zip_bytes([{"name": name, "data": data, "method": method, "descriptor": descriptor and method == "deflate"}
                      for name, data in parts.items()])


def with_parts(**replacements):
    parts = fixture()
    for name, content in replacements.items():
        parts[name] = content
    return parts


def replaced(part, old, new, parts=None):
    parts = parts or fixture()
    assert old in parts[part], (part, old)
    parts[part] = parts[part].replace(old, new)
    return parts


def noise(size, seed=42):
    state = seed
    out = bytearray()
    while len(out) < size:
        state = (state * 6364136223846793005 + 1442695040888963407) % (1 << 64)
        out += state.to_bytes(8, "little")
    return bytes(out[:size])


workbooks = []


def workbook(name, data, max_bytes=None, limits=None):
    workbooks.append({"name": name, "xlsx": base64.b64encode(data).decode("ascii"), "maxBytes": max_bytes,
                      "limits": limits})
    return len(workbooks) - 1


def limits(**changes):
    base = {"maxEntries": 200, "maxEntryBytes": 20 * 1024 * 1024, "maxInflatedBytes": 50 * 1024 * 1024, "maxRatio": 100,
            "ratioGraceBytes": 100 * 1024, "maxElements": 5_000_000, "maxSheets": 64, "maxCells": 1_000_000,
            "maxSharedStrings": 1_000_000}
    base.update(changes)
    return base


SHEET2 = "xl/worksheets/sheet2.xml"
FIXTURE = workbook("the fixture, deflated with data descriptors", package(fixture()))
workbook("the fixture, sizes in the local headers", package(fixture(), descriptor=False))
workbook("the fixture, stored", package(fixture(), method="store"))
workbook("an unsigned data descriptor", zip_bytes(
    [{"name": n, "data": d, "descriptor": True, "signed": False} for n, d in fixture().items()]))
workbook("no central directory", zip_bytes([{"name": n, "data": d} for n, d in fixture().items()], central=False))

# What is not an .xlsx without macros.
workbook("an empty body", b"")
workbook("past the ceiling", package(fixture()), max_bytes=1000)
workbook("a compound file", bytes([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]) + b"\0" * 504)
workbook("not a zip", b"hello, workbook")
workbook("an OpenDocument spreadsheet", zip_bytes([
    {"name": "mimetype", "data": "application/vnd.oasis.opendocument.spreadsheet", "method": "store"},
    {"name": "content.xml", "data": "<office:document-content xmlns:office='urn:o'/>"}]))
workbook("macro-enabled by its main type", package(replaced(
    "[Content_Types].xml", SHEET_TYPE, "application/vnd.ms-excel.sheet.macroEnabled.main+xml")))
workbook("a VBA project", package(with_parts(**{"xl/vbaProject.bin": "VBA"})))
workbook("an Excel 4 macro sheet", package(replaced(
    "[Content_Types].xml", "</Types>",
    '<Override PartName="/xl/macrosheets/sheet1.xml" '
    'ContentType="application/vnd.ms-excel.macrosheet+xml"/></Types>')))
workbook("a binary workbook", package(replaced(
    "[Content_Types].xml", SHEET_TYPE, "application/vnd.ms-excel.sheet.binary.macroEnabled.main")))
workbook("a main part that is not a spreadsheet", package(replaced(
    "[Content_Types].xml", SHEET_TYPE, "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml")))
workbook("a template's main type", package(replaced(
    "[Content_Types].xml", SHEET_TYPE, "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml")))
no_types = fixture()
del no_types["[Content_Types].xml"]
workbook("no content types", package(no_types))
no_rels = fixture()
del no_rels["_rels/.rels"]
workbook("no package relationships", package(no_rels))
workbook("no officeDocument relationship", package(replaced("_rels/.rels", "/officeDocument", "/other")))
workbook("an external target", package(replaced(
    "xl/worksheets/_rels/sheet2.xml.rels", "</Relationships>",
    f'<Relationship Id="rId9" Type="{REL}/hyperlink" Target="https://example.invalid/x" TargetMode=" External "/>'
    "</Relationships>")))
workbook("an external target without a target", package(replaced(
    "xl/worksheets/_rels/sheet2.xml.rels", "</Relationships>",
    f'<Relationship Id="rId9" Type="{REL}/hyperlink" TargetMode="External"/></Relationships>')))

# The XML.
workbook("a DOCTYPE naming its DTD", package(replaced(
    "xl/workbook.xml", 'standalone="yes"?>', 'standalone="yes"?><!DOCTYPE workbook SYSTEM "http://example.invalid/w.dtd">')))
workbook("an internal subset and its entity", package(replaced(
    "xl/sharedStrings.xml", 'standalone="yes"?>',
    'standalone="yes"?><!DOCTYPE sst [<!ENTITY secret SYSTEM "file:///etc/passwd">]>',
    replaced("xl/sharedStrings.xml", "<t>Done</t>", "<t>&secret;</t>"))))
workbook("an undeclared entity in text", package(replaced("xl/sharedStrings.xml", "<t>Done</t>", "<t>&secret;</t>")))
workbook("an undeclared entity in an attribute", package(replaced(SHEET2, '<c r="B3" s="1"/>', '<c r="B3" s="&one;"/>')))
workbook("an end tag that does not match", package(with_parts(**{"xl/workbook.xml": "<workbook><sheets></workbook>"})))
workbook("a part cut inside a tag", package(with_parts(**{"xl/workbook.xml": DECL + f'<workbook xmlns="{MAIN}"><sheets'})))
workbook("text after the root", package(replaced("xl/workbook.xml", "</workbook>", "</workbook>trailing")))
workbook("text before the root", package(replaced("xl/workbook.xml", "\n<workbook", "\nleading<workbook")))
workbook("an empty part", package(with_parts(**{"xl/workbook.xml": ""})))
workbook("a control character in text", package(replaced("xl/sharedStrings.xml", "<t>Done</t>", "<t>Do\x01ne</t>")))
workbook("]]> in text", package(replaced("xl/sharedStrings.xml", "<t>Done</t>", "<t>Do]]>ne</t>")))
workbook("an unbound prefix", package(replaced(SHEET2, "<sheetData>", "<q:note/><sheetData>")))
workbook("a duplicate attribute", package(replaced(SHEET2, '<c r="B3" s="1"/>', '<c r="B3" s="1" s="2"/>')))
workbook("an attribute bound twice by its namespace", package(replaced(
    SHEET2, '<c r="B3" s="1"/>', '<c r="B3" xmlns:a="urn:x" xmlns:b="urn:x" a:k="1" b:k="2"/>')))
workbook("a declaration not at the start", package(replaced("xl/workbook.xml", "<sheets>", '<?xml version="1.0"?><sheets>')))
workbook("a comment with a double hyphen", package(replaced("xl/workbook.xml", "<sheets>", "<!-- a -- b --><sheets>")))
workbook("comments, a processing instruction and CDATA", package(replaced(
    "xl/sharedStrings.xml", "<t>Done</t>", "<t><!-- note --><?pi data?>Do<![CDATA[n<e>]]>&#x21;&#33;&apos;</t>")))
workbook("line ends and character references", package(replaced(
    "xl/sharedStrings.xml", "<t>Done</t>", '<t xml:space="preserve">Do\r\nne\rtwice&#13;&#10;</t>')))
workbook("attribute whitespace", package(replaced(
    "xl/workbook.xml", '<sheet name="Values"', '<sheet name="Val\tues\r\n&#9;x"', replaced(
        SHEET2, "Values!$A$1:$A$2", "'Val ues  x'!$A$1:$A$2", replaced(
            "xl/workbook.xml", "Values!$A$1:$A$2", "'Val ues  x'!$A$1:$A$2")))))
workbook("a UTF-8 byte order mark", zip_bytes(
    [{"name": n, "data": (b"\xef\xbb\xbf" + d.encode() if n == SHEET2 else d)} for n, d in fixture().items()]))
workbook("a UTF-16 part", zip_bytes(
    [{"name": n, "data": (b"\xff\xfe" + d.replace('encoding="UTF-8"', 'encoding="UTF-16"').encode("utf-16-le")
                          if n == "xl/sharedStrings.xml" else d)} for n, d in fixture().items()]))
workbook("a Latin-1 part", zip_bytes(
    [{"name": n, "data": (d.replace('encoding="UTF-8"', 'encoding="ISO-8859-1"').replace("<t>Done</t>", "<t>Fait é</t>")
                          .encode("latin-1") if n == "xl/sharedStrings.xml" else d)} for n, d in fixture().items()]))
workbook("invalid UTF-8", zip_bytes(
    [{"name": n, "data": (d.encode().replace(b"<t>Done</t>", b"<t>D\xc3one</t>") if n == "xl/sharedStrings.xml" else d)}
     for n, d in fixture().items()]))
prefixed = (DECL + f'<x:worksheet xmlns:x="{MAIN}" xmlns:r="{REL}"><x:dimension ref="A1:G11"/><x:sheetData>'
            + checklist_rows().replace("<row", "<x:row").replace("</row>", "</x:row>").replace("<c ", "<x:c ")
            .replace("</c>", "</x:c>").replace("<v>", "<x:v>").replace("</v>", "</x:v>").replace("<f>", "<x:f>")
            .replace("</f>", "</x:f>").replace("<is>", "<x:is>").replace("</is>", "</x:is>").replace("<t>", "<x:t>")
            .replace("</t>", "</x:t>")
            + "</x:sheetData>" + EXTENSION.replace("<mergeCells", "<x:mergeCells").replace("</mergeCells>",
                                                                                         "</x:mergeCells>")
            .replace("<mergeCell ", "<x:mergeCell ").replace("<legacyDrawing", "<x:legacyDrawing")
            .replace("<extLst>", "<x:extLst>").replace("</extLst>", "</x:extLst>").replace("<ext ", "<x:ext ")
            .replace("</ext>", "</x:ext>")
            + "</x:worksheet>")
PREFIXED = workbook("a prefixed worksheet", package(with_parts(**{SHEET2: prefixed})))
deep = "<a>" * 70 + "</a>" * 70
workbook("elements nested deeper than 64", package(replaced(SHEET2, "</sheetData>", "</sheetData>" + deep)))
many = " ".join(f'a{i}="{i}"' for i in range(64))
workbook("an element with 65 attributes, its reference one of them", package(replaced(SHEET2, '<c r="B3" s="1"/>', f'<c r="B3" {many}/>')))
many_with_namespaces = " ".join(f'xmlns:p{i}="urn:p{i}"' for i in range(10)) + " " + " ".join(
    f'a{i}="{i}"' for i in range(60))
workbook("60 attributes and 10 namespace declarations", package(replaced(
    SHEET2, '<c r="B3" s="1"/>', f'<c r="B3" {many_with_namespaces}/>')))
workbook("a row whose prefix shares its attribute's name", package(replaced(
    SHEET2, '<row r="3">', '<row xmlns:r="urn:shadow" r="3">')))
workbook("an attribute prefixed r named r", package(replaced(SHEET2, '<row r="4">', '<row r:r="9" r="4">')))
workbook("an xml prefix bound elsewhere", package(replaced(SHEET2, "<sheetData>", '<sheetData xmlns:xml="urn:no">')))
workbook("XML 1.1", package(replaced("xl/workbook.xml", 'version="1.0"', 'version="1.1"')))
workbook("XML 2.0", package(replaced("xl/workbook.xml", 'version="1.0"', 'version="2.0"')))

# The XML parser's edges, each in the first sheet's part.
XML_EDGES = [
    ("an unquoted attribute", '<worksheet xmlns="%s"><sheetData b=1/></worksheet>'),
    ("a < in an attribute", '<worksheet xmlns="%s"><sheetData b="<"/></worksheet>'),
    ("a reference to character 0", '<worksheet xmlns="%s"><sheetData>&#0;</sheetData></worksheet>'),
    ("a reference to a surrogate", '<worksheet xmlns="%s"><sheetData>&#xD800;</sheetData></worksheet>'),
    ("a reference past Unicode", '<worksheet xmlns="%s"><sheetData>&#x110000;</sheetData></worksheet>'),
    ("a reference without its semicolon", '<worksheet xmlns="%s"><sheetData>&amp x</sheetData></worksheet>'),
    ("a hexadecimal reference in capitals", '<worksheet xmlns="%s"><sheetData>&#X41;</sheetData></worksheet>'),
    ("attributes without a space between them", '<worksheet xmlns="%s"><sheetData a="1"b="2"/></worksheet>'),
    ("a name starting with a digit", '<worksheet xmlns="%s"><1a/></worksheet>'),
    ("a name with two colons", '<worksheet xmlns="%s" xmlns:a="u"><a:b:c/></worksheet>'),
    ("a name starting with a colon", '<worksheet xmlns="%s"><:a/></worksheet>'),
    ("a prefix bound to nothing", '<worksheet xmlns="%s" xmlns:p=""><sheetData/></worksheet>'),
    ("the default namespace unbound", '<worksheet xmlns="%s"><sheetData xmlns=""/></worksheet>'),
    ("a prefix bound to the xmlns namespace", '<worksheet xmlns="%s" xmlns:p="http://www.w3.org/2000/xmlns/"/>'),
    ("the xmlns prefix declared", '<worksheet xmlns="%s" xmlns:xmlns="urn:x"/>'),
    ("the xml prefix bound to its own namespace", '<worksheet xmlns="%s" xmlns:xml="http://www.w3.org/XML/1998/namespace"/>'),
    ("an xml:lang attribute", '<worksheet xmlns="%s" xml:lang="en"/>'),
    ("a declaration whose standalone is neither", '<?xml version="1.0" standalone="maybe"?><worksheet xmlns="%s"/>'),
    ("a declaration out of order", '<?xml version="1.0" standalone="yes" encoding="UTF-8"?><worksheet xmlns="%s"/>'),
    ("a declaration without a version", '<?xml encoding="UTF-8"?><worksheet xmlns="%s"/>'),
    ("a declaration with single quotes", "<?xml version='1.0' encoding='utf-8'?><worksheet xmlns=\"%s\"/>"),
    ("whitespace before the declaration", ' <?xml version="1.0"?><worksheet xmlns="%s"/>'),
    ("a processing instruction named xml in any case", '<worksheet xmlns="%s"><?XmL x?></worksheet>'),
    ("a processing instruction without data", '<worksheet xmlns="%s"><?pi?></worksheet>'),
    ("a processing instruction before the root", '<?xml version="1.0"?><?pi x?><!-- c --><worksheet xmlns="%s"/>'),
    ("CDATA after the root", '<worksheet xmlns="%s"/><![CDATA[x]]>'),
    ("a comment after the root", '<worksheet xmlns="%s"/><!-- end -->\n'),
    ("a comment ending in three hyphens", '<worksheet xmlns="%s"><!-- x ---></worksheet>'),
    ("an element left open", '<worksheet xmlns="%s"><sheetData>'),
    ("an end tag with a space", '<worksheet xmlns="%s"><sheetData></sheetData ></worksheet >'),
    ("an end tag without its element", '<worksheet xmlns="%s"></sheetData></worksheet>'),
    ("names outside ASCII", '<worksheet xmlns="%s"><données é="1"/></worksheet>'),
    ("U+FFFE in text", '<worksheet xmlns="%s"><sheetData>\ufffe</sheetData></worksheet>'),
    ("a namespace declared twice", '<worksheet xmlns="%s" xmlns:a="x" xmlns:a="y"/>'),
    ("a second root", '<worksheet xmlns="%s"/><worksheet/>'),
    ("a DOCTYPE after the root", '<worksheet xmlns="%s"/><!DOCTYPE x>'),
    ("a markup declaration in content", '<worksheet xmlns="%s"><!ELEMENT x ANY></worksheet>'),
    ("CDATA left open", '<worksheet xmlns="%s"><![CDATA[x</worksheet>'),
    ("a comment left open", '<worksheet xmlns="%s"><!-- x</worksheet>'),
    ("an attribute without a value", '<worksheet xmlns="%s"><sheetData a/></worksheet>'),
    ("a space before the equals sign", '<worksheet xmlns="%s"><sheetData a = "1" /></worksheet>'),
    ("a tab and line ends inside a tag", '<worksheet\txmlns="%s"\r\n><sheetData\n/></worksheet>'),
    ("an encoding declared windows-1252", '<?xml version="1.0" encoding="windows-1252"?><worksheet xmlns="%s"/>'),
    ("an encoding declared UTF-16 without a mark", '<?xml version="1.0" encoding="UTF-16"?><worksheet xmlns="%s"/>'),
    ("a form feed in text", '<worksheet xmlns="%s"><sheetData>\x0c</sheetData></worksheet>'),
    ("a version of 1.10", '<?xml version="1.10"?><worksheet xmlns="%s"/>'),
    ("a declaration with no space before ?>", '<?xml version="1.0"?><worksheet xmlns="%s"/>'),
    ("a declaration ending in a space", '<?xml version="1.0" ?><worksheet xmlns="%s"/>'),
    ("an encoding starting with a digit", '<?xml version="1.0" encoding="8859_1"?><worksheet xmlns="%s"/>'),
    ("an empty document but a comment", '<!-- nothing -->'),
    ("a name ending with a colon", '<worksheet xmlns="%s" xmlns:a="u"><a:/></worksheet>'),
    ("an attribute name with two colons", '<worksheet xmlns="%s" xmlns:a="u"><sheetData a:b:c="1"/></worksheet>'),
    ("an attribute named with a colon first", '<worksheet xmlns="%s"><sheetData :a="1"/></worksheet>'),
    ("windows-1252", '<?xml version="1.0" encoding="windows-1252"?><worksheet xmlns="%s"><sheetData>\x80\x81</sheetData>'
                     '</worksheet>'),
    ("a name of a namespace declaration without a prefix", '<worksheet xmlns="%s" xmlns:="u"/>'),
    ("a root named with a colon first, no namespace", '<:worksheet/>'),
    ("a character reference in a name's place", '<worksheet xmlns="%s"><sheetData>&#;</sheetData></worksheet>'),
]
for name, body in XML_EDGES:
    text = body.replace("%s", MAIN)
    if name == "windows-1252":
        parts = {n: d.encode() for n, d in fixture().items()}
        parts["xl/worksheets/sheet1.xml"] = text.encode("latin-1")
        workbook(name, zip_bytes([{"name": n, "data": d} for n, d in parts.items()]))
    else:
        workbook(name, package(with_parts(**{"xl/worksheets/sheet1.xml": text})))

# The cells.
workbook("a shared string the table does not hold", package(with_parts(
    **{"xl/worksheets/sheet1.xml": sheet(row(1, s("A1", 999)))})))
workbook("a cell's text past 32,767 characters", package(with_parts(**{"xl/worksheets/sheet1.xml": sheet(
    row(1, '<c r="A1" t="inlineStr"><is><t>' + "x" * 32_768 + "</t></is></c>"))})))
workbook("a cell's text of 32,767 characters in two runs", package(with_parts(**{"xl/worksheets/sheet1.xml": sheet(
    row(1, '<c r="A1" t="inlineStr"><is><r><t>' + "x" * 16_000 + "</t></r><r><t>" + "y" * 16_767
        + "</t></r></is></c>"))})))
workbook("cells placed by their order alone", package(with_parts(**{"xl/worksheets/sheet1.xml": sheet(
    '<row><c t="inlineStr"><is><t>a</t></is></c><c t="inlineStr"><is><t>b</t></is></c></row>'
    '<row r="5"><c r="C5"><v> 7 </v></c><c><v>8</v></c></row><row><c><v>9</v></c></row>')})))
workbook("types: booleans, errors, strings, dates, formulas", package(with_parts(**{"xl/worksheets/sheet1.xml": sheet(
    row(1, '<c r="A1" t="b"><v>1</v></c><c r="B1" t="b"><v> TRUE </v></c><c r="C1" t="b"><v>0</v></c>'
        '<c r="D1" t="e"><v> #N/A </v></c><c r="E1" t="str"><v> text </v></c><c r="F1" t="d"><v>2026-01-01</v></c>'
        '<c r="G1" t="b"><f>1=1</f><v>1</v></c><c r="H1"><f t="shared" ref="H1:H2" si="0"> A1+1 </f><v>2</v></c>'
        '<c r="I1"><f/></c><c r="J1" t="s"/><c r="K1" t="e"/><c r="L1"><v>   </v></c><c r="M1" t="inlineStr"/>'
        '<c r="N1" t="s"><v> 0 </v></c>')
    + row(2, '<c r="H2"><f t="shared" si="0"/><v>3</v></c><c r="A2" t="b"><v>yes</v></c>'))})))
workbook("a shared string index with a sign", package(with_parts(**{"xl/worksheets/sheet1.xml": sheet(
    row(1, '<c r="A1" t="s"><v>-1</v></c>'))})))
workbook("a cell reference that is none", package(with_parts(**{"xl/worksheets/sheet1.xml": sheet(
    row(1, '<c r="A0"><v>1</v></c>'))})))
workbook("a row numbered past the grid", package(with_parts(**{"xl/worksheets/sheet1.xml": sheet(
    '<row r="1048577"><c r="A1"><v>1</v></c></row>')})))
workbook("a row numbered with a sign", package(with_parts(**{"xl/worksheets/sheet1.xml": sheet(
    '<row r="+3"><c r="A3"><v>1</v></c></row>')})))
workbook("a cell outside any row", package(with_parts(**{"xl/worksheets/sheet1.xml": sheet(
    '<row r="1"><c r="XFD1"><v>1</v></c><c><v>2</v></c></row>')})))
workbook("an implied row past the grid", package(with_parts(**{"xl/worksheets/sheet1.xml": sheet(
    '<row r="1048576"><c r="A1048576"><v>1</v></c></row><row><c><v>2</v></c></row>')})))
workbook("the same cell twice", package(with_parts(**{"xl/worksheets/sheet1.xml": sheet(
    row(1, '<c r="A1"><v>1</v></c><c r="A1"><v>2</v></c>'))})))
LISTS = ('<dataValidations count="8">'
         '<dataValidation type="list" sqref="B1:B5"><formula1>"Yes,No,,Yes, Maybe "</formula1></dataValidation>'
         '<dataValidation type="list" sqref="C1:C5 junk D1"><formula1>AnswerWords</formula1></dataValidation>'
         '<dataValidation type="list" sqref="E1"><formula1>$A$1:$A$9</formula1></dataValidation>'
         '<dataValidation type="list" sqref="F1"><formula1>INDIRECT("x")</formula1></dataValidation>'
         '<dataValidation type="whole" sqref="G1"><formula1>1</formula1></dataValidation>'
         '<dataValidation type="list" sqref="H1"><formula1>Loop</formula1></dataValidation>'
         '<dataValidation type="list" sqref="I1:J1"><formula1>"a""b,c"</formula1></dataValidation>'
         '<dataValidation type="list" sqref="nothing"><formula1>"x"</formula1></dataValidation>'
         '<dataValidation type="list" sqref="K1"><formula1>=Values!A1:A1048576</formula1></dataValidation>'
         '<dataValidation type="list" sqref="L1"><formula1>Nowhere!A1:A2</formula1></dataValidation>'
         '</dataValidations>')
lists = replaced("xl/workbook.xml", "</definedNames>",
                 '<definedName name="Loop">Loop</definedName>'
                 '<definedName name="AnswerWords"> =Values!$A$1:$A$2 </definedName></definedNames>')
lists["xl/worksheets/sheet1.xml"] = sheet(
    row(1, s("A1", 24)) + row(2, s("A2", 25)) + row(3, s("A3", 24))
    + row(4, '<c r="A4" t="inlineStr"><is><t> </t></is></c>'), LISTS)
workbook("lists of every kind", package(lists))
workbook("a chart sheet, a sheet without a part, two names alike", package(replaced(
    "xl/workbook.xml", '<sheet name="Values" sheetId="3" r:id="rId3"/>',
    '<sheet name="Values" sheetId="3" r:id="rId3"/><sheet name="Chart" sheetId="4" r:id="rId5"/>', replaced(
        "xl/_rels/workbook.xml.rels", "</Relationships>",
        f'<Relationship Id="rId5" Type="{REL}/chartsheet" Target="chartsheets/sheet1.xml"/></Relationships>'))))
workbook("a sheet pointing at no part", package(replaced(
    "xl/workbook.xml", '<sheet name="Values" sheetId="3" r:id="rId3"/>',
    '<sheet name="Values" sheetId="3" r:id="rId3"/><sheet name="Lost" sheetId="4" r:id="rId9"/>')))
workbook("two sheets named alike", package(replaced(
    "xl/workbook.xml", '<sheet name="Values" sheetId="3" r:id="rId3"/>',
    '<sheet name="Values" sheetId="3" r:id="rId3"/><sheet name="VALUES" sheetId="4" r:id="rId1"/>')))
workbook("a sheet without a name", package(replaced("xl/workbook.xml", '<sheet name="Values" ', "<sheet ")))
workbook("no worksheet", package(replaced(
    "xl/_rels/workbook.xml.rels", "/worksheet\"", "/chartsheet\"")))
workbook("a part the package does not hold", package(replaced(
    "xl/_rels/workbook.xml.rels", "worksheets/sheet1.xml", "worksheets/missing.xml")))
workbook("percent escapes, dot segments and case in targets", package(replaced(
    "xl/_rels/workbook.xml.rels", 'Target="worksheets/sheet1.xml"', 'Target=" ./Worksheets/../worksheets/SHEET%31.xml "',
    replaced("[Content_Types].xml", "/xl/worksheets/sheet1.xml", "/XL/worksheets/sheet%311.xml"))))
# rId9 comes first in the file and second in Java's HashMap (buckets 8 and 3): the map's order decides.
two_strings = replaced("xl/_rels/workbook.xml.rels", f'<Relationships xmlns="{PACKAGE_REL}">',
                       f'<Relationships xmlns="{PACKAGE_REL}">'
                       f'<Relationship Id="rId9" Type="{REL}/sharedStrings" Target="strings2.xml"/>')
two_strings["xl/strings2.xml"] = shared_strings(["Other"] * 30)
workbook("two shared-strings relationships", package(two_strings))
workbook("a defined name scoped to a sheet, and one repeated", package(replaced(
    "xl/workbook.xml", "</definedNames>",
    '<definedName name="AnswerWords">  Values!$A$2  </definedName><definedName>nameless</definedName></definedNames>')))

# The zip's guards.
many_parts = fixture()
for i in range(len(many_parts), 201):
    many_parts[f"xl/media/image{i}.png"] = ""
workbook("more entries than a workbook has", package(many_parts))
bomb = {n: d.encode() for n, d in fixture().items()}
bomb["xl/media/image1.png"] = b"\0" * (5 * 1024 * 1024)
workbook("an entry inflating a hundred times its size", zip_bytes(
    [{"name": n, "data": d} for n, d in bomb.items()]))
grace = {n: d.encode() for n, d in fixture().items()}
grace["xl/printerSettings/printerSettings1.bin"] = b"\0" * (100 * 1024)
workbook("a small part within the grace", zip_bytes([{"name": n, "data": d} for n, d in grace.items()]))
edge = {n: d.encode() for n, d in fixture().items()}
edge["xl/media/edge.bin"] = b"\0" * (100 * 1024 + 1)
workbook("a part one byte past the grace", zip_bytes([{"name": n, "data": d} for n, d in edge.items()]))
stored_noise = [{"name": n, "data": d} for n, d in fixture().items()] + [
    {"name": "xl/media/image1.png", "data": noise(16 * 1024), "method": "store"}]
workbook("one entry past its ceiling", zip_bytes(stored_noise), limits=limits(maxEntryBytes=8 * 1024, maxCells=1000,
                                                                               maxSharedStrings=1000))
total = [{"name": n, "data": d} for n, d in fixture().items()] + [
    {"name": "xl/media/a.png", "data": noise(10 * 1024, 1), "method": "store"},
    {"name": "xl/media/b.png", "data": noise(10 * 1024, 2), "method": "store"}]
workbook("every entry together past the ceiling", zip_bytes(total), limits=limits(
    maxEntryBytes=16 * 1024, maxInflatedBytes=16 * 1024, maxCells=1000, maxSharedStrings=1000))
workbook("an archive inside, by its name", package(with_parts(**{"xl/embeddings/Other_Workbook.XLSX": "whatever"})))
inner = zip_bytes([{"name": "inner.txt", "data": b"\0" * 10}])
workbook("an archive inside, by its first bytes", zip_bytes(
    [{"name": n, "data": d} for n, d in fixture().items()] + [{"name": "xl/media/image1.png", "data": inner}]))
dup = fixture()
dup["xl/Workbook.xml"] = dup["xl/workbook.xml"]
workbook("a part held twice", package(dup))
workbook("a directory entry held twice", zip_bytes(
    [{"name": "xl/", "data": b""}, {"name": "XL/", "data": b""}] + [{"name": n, "data": d} for n, d in fixture().items()]))
workbook("directory entries", zip_bytes(
    [{"name": "xl/", "data": b"", "method": "store"}, {"name": "docProps/", "data": b""}]
    + [{"name": n, "data": d} for n, d in fixture().items()]))
fixture_bytes = package(fixture())
for name, sheets, cells, strings, elements in [
        ("more than 2 sheets", 2, 1000, 1000, 5_000_000), ("more than 20 cells", 64, 20, 1000, 5_000_000),
        ("more than 10 shared strings", 64, 1000, 10, 5_000_000), ("more than 50 XML elements", 64, 1000, 1000, 50)]:
    workbook(name, fixture_bytes, limits=limits(maxSheets=sheets, maxCells=cells, maxSharedStrings=strings,
                                                maxElements=elements))
workbook("an archive cut inside an entry", fixture_bytes[: len(fixture_bytes) // 2])
workbook("an archive cut inside a local header", fixture_bytes[:20])
workbook("an archive cut inside a name", zip_bytes([{"name": "a" * 40, "data": "x"}])[:35])
workbook("an archive cut inside a data descriptor", zip_bytes(
    [{"name": "[Content_Types].xml", "data": "<x/>", "descriptor": True}], central=False)[:-6])
workbook("a wrong CRC", zip_bytes([{"name": n, "data": d, "crc": 1 if n == SHEET2 else zlib.crc32(d.encode())}
                                   for n, d in fixture().items()]))
workbook("a wrong stored CRC", zip_bytes([{"name": n, "data": d, "method": "store",
                                          "crc": 1 if n == SHEET2 else zlib.crc32(d.encode())}
                                         for n, d in fixture().items()]))
workbook("a wrong size", zip_bytes([{"name": n, "data": d, "size": 3 if n == SHEET2 else len(d.encode())}
                                    for n, d in fixture().items()]))
workbook("an encrypted entry", zip_bytes([{"name": n, "data": d, "flag": 1 if n == SHEET2 else 0}
                                          for n, d in fixture().items()]))
workbook("an unknown method", zip_bytes([{"name": n, "data": d, "method": 12 if n == "xl/drawings/vmlDrawing1.vml" else
                                          "deflate"} for n, d in fixture().items()]))
workbook("a stored entry with a data descriptor", zip_bytes(
    [{"name": n, "data": d, "method": "store", "descriptor": n == SHEET2} for n, d in fixture().items()]))
workbook("a name that is not UTF-8", zip_bytes(
    [{"name": n, "data": d} for n, d in fixture().items()] + [{"name": "", "raw_name": b"xl/\xff.bin", "data": "x"}]))
workbook("a header cut short at the start", b"PK\x03\x04" + b"\0" * 10)
workbook("a stored entry longer than the archive", zip_bytes(
    [{"name": n, "data": d} for n, d in fixture().items()]
    + [{"name": "xl/media/x.bin", "data": b"abc", "method": "store", "size": 1000, "csize": 1000}], central=False))
workbook("deflated garbage", zip_bytes([{"name": "[Content_Types].xml", "data": b"", "method": 8, "csize": 4}])
         [:30 + 19] + b"\xff\xff\xff\xff" + b"PK\x01\x02" + b"\0" * 60)
workbook("a long name past the header's ceiling", zip_bytes(
    [{"name": "x" * 65_500, "data": "x"}] + [{"name": n, "data": d} for n, d in fixture().items()], central=False))
workbook("an extra field past the header's ceiling", zip_bytes(
    [{"name": "x" * 400, "data": "x", "extra": struct.pack("<HH", 0x9999, 65_100) + b"\0" * 65_100}]
    + [{"name": n, "data": d} for n, d in fixture().items()], central=False))
workbook("a ZIP64 extra field on a stored entry", zip_bytes(
    [{"name": n, "data": d} for n, d in fixture().items()]
    + [{"name": "xl/media/z.bin", "data": b"abcdef", "method": "store", "size": 0xFFFFFFFF, "csize": 0xFFFFFFFF,
        "extra": struct.pack("<HHqq", 1, 16, 6, 6)}]))

# Proposals worth their own workbook.
id_parts = fixture()
id_parts[SHEET2] = sheet(
    row(1, s("A1", 1)) + '<row r="2">' + s("A2", 2) + '<c r="B2" s="3"><f>TODAY()</f><v>46293</v></c></row>'
    + row(3, s("A3", 3)) + row(4, s("A4", 4))
    + row(6, '<c r="A6" t="inlineStr"><is><t>Id</t></is></c>' + s("B6", 5) + s("C6", 6) + s("D6", 7) + s("E6", 8)
          + s("F6", 9) + s("G6", 10) + s("H6", 11))
    + "".join(row(r, f'<c r="A{r}" t="inlineStr"><is><t>SEC-0{r}</t></is></c>'
                  + (s(f"B{r}", 12) + s(f"C{r}", 13) if r == 7 else "") + s(f"D{r}", 14 + (r % 3)) + s(f"E{r}", 15))
              for r in range(7, 12)),
    EXTENSION.replace("F7:F11", "G7:G11"))
ID_COLUMN = workbook("an identifier column in front of the domain", package(id_parts))
plain = fixture()
plain[SHEET2] = sheet(checklist_rows(), '<mergeCells count="1"><mergeCell ref="A1:G1"/></mergeCells>')
plain["xl/worksheets/sheet3.xml"] = sheet(row(1, s("A1", 24)))
PLAIN = workbook("no validation", package(plain))
workbook("no header row", package(with_parts(**{SHEET2: sheet(row(1, s("A1", 1))),
                                                "xl/worksheets/sheet1.xml": sheet(row(1, s("A1", 0)))})))
prose = fixture()
prose[SHEET2] = prose[SHEET2].replace('<row r="4">', '<row r="5">' + s("A5", 0) + s("B5", 0) + "</row><row r=\"4\">")
workbook("prose above the header", package(prose))
workbook("a header row on the last row of the grid", package(with_parts(**{"xl/worksheets/sheet1.xml": sheet(
    '<row r="1048576">' + s("A1048576", 5) + s("B1048576", 6) + s("C1048576", 7) + "</row>")})))
headers = fixture()
headers[SHEET2] = headers[SHEET2].replace(
    row(3, s("A3", 3) + '<c r="B3" s="1"/>'),
    row(3, s("A3", 3) + '<c r="B3" t="inlineStr"><is><t>value</t></is></c>' + s("D3", 4) + '<c r="E3"><v>5</v></c>'))
headers[SHEET2] = headers[SHEET2].replace('<mergeCell ref="A1:G1"/>', '<mergeCell ref="A1:G1"/><mergeCell ref="A4:B4"/>')
narrow = fixture()
narrow[SHEET2] = sheet(
    row(2, s("A2", 5) + s("B2", 6) + s("C2", 7) + s("D2", 8)) + row(3, s("A3", 12)) + row(4, s("A4", 12))
    + row(6, s("A6", 5) + s("B6", 6) + s("C6", 7)) + "".join(row(r, s(f"A{r}", 13)) for r in range(7, 13)))
narrow["xl/worksheets/sheet3.xml"] = sheet(row(1, s("A1", 24)))
workbook("a wide header with a short run above a narrower one with a long run", package(narrow))
HEADERS = workbook("header pairs, a merged label, a number beside a label", package(headers))

# The renderer's workbooks.
DATE1904 = workbook("a 1904 workbook", package(replaced(
    "xl/workbook.xml", "<sheets>", '<workbookPr date1904="true"/><sheets>')))
chain = fixture()
chain["xl/calcChain.xml"] = DECL + f'<calcChain xmlns="{MAIN}"><c r="B2" i="2"/></calcChain>'
chain["[Content_Types].xml"] = chain["[Content_Types].xml"].replace("</Types>", (
    '<Override PartName="/xl/calcChain.xml" '
    'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.calcChain+xml"/></Types>'))
chain["xl/_rels/workbook.xml.rels"] = chain["xl/_rels/workbook.xml.rels"].replace("</Relationships>", (
    f'<Relationship Id="rId5" Type="{REL}/calcChain" Target="calcChain.xml"></Relationship></Relationships>'))
CHAIN = workbook("a calculation chain", package(chain))
shared = replaced(SHEET2, "<f>TODAY()</f>", '<f t="shared" ref="B2:C2" si="0">TODAY()</f>')
shared[SHEET2] = (shared[SHEET2]
                  .replace('<c r="D7" t="s"><v>15</v></c></row>',
                           '<c r="D7" t="s"><v>15</v></c><c r="G7"><f t="shared" ref="G7:G8" si="1">LEN(F7)</f>'
                           '<v>0</v></c></row>')
                  .replace('<c r="E8" t="s"><v>17</v></c></row>',
                           '<c r="E8" t="s"><v>17</v></c><c r="G8"><f t="shared" si="1"/><v>0</v></c></row>')
                  .replace('<c r="D9" t="s"><v>19</v></c></row>',
                           '<c r="D9" t="s"><v>19</v></c><c r="G9"><f t="array" ref="G9:G10">ROW(A1:A2)</f><v>1</v>'
                           '</c></row>')
                  .replace('<c r="D10" t="s"><v>19</v></c>',
                           '<c r="D10" t="s"><v>19</v></c><c r="F10"><f t="array" ref="F10">1</f><v>1</v></c>'))
SHARED = workbook("formulas others depend on", package(shared))
many_masters = fixture()
many_masters[SHEET2] = sheet("".join(
    row(r, s(f"C{r}", 14) + f'<c r="F{r}"><f t="shared" ref="F{r}:H{r}" si="{r}">1</f></c>') for r in range(7, 20)))
MASTERS = workbook("eleven masters and more", package(many_masters))
spliced = fixture()
spliced[SHEET2] = sheet(
    row(1, s("A1", 1))
    + '<row r="2" spans="1:2">' + s("A2", 2) + '<c r="B2" s="3"><f>TODAY()</f><v>46293</v></c></row>'
    + '<row r="6" spans="1:7 9:9">' + s("A6", 5) + s("C6", 7) + s("F6", 10) + "</row>"
    + '<row spans="1:3">' + s("C7", 14) + '<c s="5" t="s"><v>15</v></c><c r="G7" s="&amp;7"/></row>'
    + '<row r="9" spans="x"/>'
    + "<row>" + s("C10", 23) + "</row>"
    + '<row r="11" spans=":">' + '<c r="A11"/>' + s("C11", 16) + '<c t="inlineStr"><is><t>e</t></is></c>'
    + '<c r="H11"><v>1</v></c></row>',
    "", '<dimension ref="A1:C3"/><sheetViews><sheetView workbookViewId="0"/></sheetViews>')
SPLICED = workbook("rows and cells to insert, spans, the dimension", package(spliced))
EMPTY_DATA = workbook("an empty sheetData", package(with_parts(**{SHEET2: sheet("").replace(
    "<sheetData></sheetData>", "<sheetData/>")})))
NO_DATA = workbook("no sheetData", package(with_parts(**{SHEET2: DECL + f'<worksheet xmlns="{MAIN}"/>'})))
taken = replaced("xl/workbook.xml", '<sheet name="Values" sheetId="3" r:id="rId3"/>',
                 '<sheet name="Values" sheetId="x" r:id="rId3"/><sheet name="evidence" sheetId=" 7 " r:id="rId6"/>'
                 '<sheet name="Evidence (2)" sheetId="2147483647" r:id="rId7"/>')
taken["xl/_rels/workbook.xml.rels"] = taken["xl/_rels/workbook.xml.rels"].replace("</Relationships>", (
    f'<Relationship Id="rId6" Type="{REL}/worksheet" Target="worksheets/sheet4.xml"/>'
    f'<Relationship Id="rId7" Type="{REL}/worksheet" Target="worksheets/sheet6.xml"/></Relationships>'))
taken["xl/worksheets/sheet4.xml"] = sheet("")
taken["xl/worksheets/sheet6.xml"] = sheet("")
taken["xl/worksheets/sheet7.xml"] = "<unlisted/>"
TAKEN = workbook("an Evidence sheet, its part and its number taken", package(taken))
book = replaced("xl/workbook.xml", f'<workbook xmlns="{MAIN}" xmlns:r="{REL}"><sheets>',
                f'<x:workbook xmlns:x="{MAIN}"><x:sheets>')
book["xl/workbook.xml"] = (book["xl/workbook.xml"]
                           .replace('<sheet name="Instructions" sheetId="1" r:id="rId1"/>',
                                    f'<x:sheet xmlns:rel="{REL}" name="Instructions" sheetId="1" rel:id="rId1"/>')
                           .replace('<sheet name="Checklist" sheetId="2" r:id="rId2"/>',
                                    f'<x:sheet xmlns:rel="{REL}" name="Checklist" sheetId="2" rel:id="rId2"/>')
                           .replace('<sheet name="Values" sheetId="3" r:id="rId3"/>',
                                    f'<x:sheet xmlns:rel="{REL}" name="Values" sheetId="3" rel:id="rId3"/>')
                           .replace("</sheets>", "</x:sheets>").replace("<definedNames>", "<x:definedNames>")
                           .replace("</definedNames>", "</x:definedNames>").replace("<definedName ", "<x:definedName ")
                           .replace("</definedName>", "</x:definedName>").replace("<calcPr ", "<x:calcPr ")
                           .replace("</workbook>", "</x:workbook>"))
book["[Content_Types].xml"] = book["[Content_Types].xml"].replace(
    f'<Override PartName="/xl/worksheets/sheet2.xml" ContentType="{WORKSHEET_TYPE}"/>',
    '<Override PartName="/xl/worksheets/sheet2.xml" ContentType=" application/vnd.custom+xml "/>').replace(
    "<Types ", "<ct:Types xmlns:ct=\"http://schemas.openxmlformats.org/package/2006/content-types\" ").replace(
    "</Types>", "</ct:Types>").replace('xmlns="http://schemas.openxmlformats.org/package/2006/content-types"', "")
book["[Content_Types].xml"] = book["[Content_Types].xml"].replace("<Default ", "<ct:Default ").replace(
    "<Override ", "<ct:Override ")
PREFIXED_BOOK = workbook("a prefixed workbook, its sheets declaring their own namespace", package(book))
bom = fixture()
BOM = workbook("byte order marks on the parts written", zip_bytes(
    [{"name": n, "data": (b"\xef\xbb\xbf" + d.encode() if n in (SHEET2, "xl/workbook.xml", "[Content_Types].xml")
                          else d)} for n, d in bom.items()]))
utf16_sheet = fixture()
UTF16_SHEET = workbook("a checklist sheet in UTF-16", zip_bytes(
    [{"name": n, "data": (b"\xff\xfe" + d.replace('encoding="UTF-8"', 'encoding="UTF-16"').encode("utf-16-le")
                          if n == SHEET2 else d)} for n, d in utf16_sheet.items()]))
LATIN1_SHEET = workbook("a checklist sheet declared Latin-1", zip_bytes(
    [{"name": n, "data": (d.replace('encoding="UTF-8"', 'encoding="ISO-8859-1"').encode("latin-1")
                          if n == SHEET2 else d)} for n, d in fixture().items()]))
STORED_FOLDERS = workbook("stored entries and folders, copied as they are", zip_bytes(
    [{"name": "xl/", "data": b"", "method": "store"}]
    + [{"name": n, "data": d, "method": "store" if n.endswith(".vml") else "deflate"} for n, d in fixture().items()]))
selfclosed = replaced("[Content_Types].xml", "</Types>", "</Types>")
selfclosed["xl/_rels/workbook.xml.rels"] = DECL + f'<Relationships xmlns="{PACKAGE_REL}">' + "".join(
    f'<Relationship Id="rId{i}" Type="{REL}/worksheet" Target="worksheets/sheet{i}.xml"/>' for i in (1, 2, 3)) + \
    f'<Relationship Id="rId4" Type="{REL}/sharedStrings" Target="sharedStrings.xml"/></Relationships>'
SELF_CLOSED = workbook("an empty row element among the items", package(replaced(
    SHEET2, row(9, s("B9", 18) + s("C9", 20) + s("D9", 19)), row(9, s("B9", 18) + s("C9", 20) + s("D9", 19)).replace(
        '<row r="9">', '<row r="9" spans="2:4">'), replaced(SHEET2, row(8, '<c r="A8" s="1"/>' + s("C8", 16) + s(
            "D8", 15) + s("E8", 17)), '<row r="8"/>', selfclosed))))
NO_FOLDER = workbook("a workbook part at the package's root", package({
    "[Content_Types].xml": fixture()["[Content_Types].xml"].replace("/xl/workbook.xml", "/workbook.xml").replace(
        "/xl/worksheets/sheet2.xml", "/sheet2.xml"),
    "_rels/.rels": fixture()["_rels/.rels"].replace("xl/workbook.xml", "workbook.xml"),
    "workbook.xml": fixture()["xl/workbook.xml"].replace('<sheet name="Instructions" sheetId="1" r:id="rId1"/>', "")
    .replace('<sheet name="Values" sheetId="3" r:id="rId3"/>', ""),
    "_rels/workbook.xml.rels": DECL + f'<Relationships xmlns="{PACKAGE_REL}">'
    f'<Relationship Id="rId2" Type="{REL}/worksheet" Target="sheet2.xml"/>'
    f'<Relationship Id="rId4" Type="{REL}/sharedStrings" Target="xl/sharedStrings.xml"/></Relationships>',
    "xl/sharedStrings.xml": shared_strings(),
    "sheet2.xml": sheet(checklist_rows()),
}))

# ---------------------------------------------------------------- layouts


def layout(columns=None, first=7, last=11, header=None, answers=("Done", "Not done", None), sheet_name="Checklist"):
    columns = columns if columns is not None else [
        ["domain", "A"], ["objective", "B"], ["control", "C"], ["contact", "D"], ["kpi", "E"], ["answer", "F"],
        ["comment", "G"]]
    header = header if header is not None else [["date", "A2", "B2"], ["product", "A3", "B3"], ["author", "A4", "B4"]]
    return {"sheet": sheet_name, "columns": columns, "firstItemRow": first, "lastItemRow": last, "header": header,
            "answers": list(answers)}


STANDARD = layout()
layouts = [
    STANDARD,
    layout(sheet_name=None), layout(sheet_name="  "), layout(sheet_name="x" * 31), layout(sheet_name="x" * 32),
    layout(sheet_name="\U0001F600" * 16),
    layout(columns=[["control", "C"], ["answer", "F"]]),
    layout(columns=[["control", "c"], ["answer", " f "], ["comment", "$G"]]),
    layout(columns=[["control", "C"], ["answer", "F"], ["comment", None]]),
    layout(columns=[["control", "C"], ["answer", "F"], ["comment", "XFE"]]),
    layout(columns=[["control", "C"], ["answer", "F"], ["comment", "ＡＢ"]]),
    layout(columns=[["comment", "C"], ["answer", "F"], ["control", "c"]]),
    layout(columns=[["kpi", "AA"], ["control", "C"], ["answer", "F"], ["comment", "G"], ["id", "aa"]]),
    layout(first=0), layout(first=5, last=4), layout(last=1_048_577), layout(first=1, last=5000),
    layout(first=1, last=5001),
    layout(header=[["product", "A7", "B3"]]), layout(header=[["author", "A3", "B11"]]),
    layout(header=[["date", "A2", "B2"], ["author", "C2", "B2"]]),
    layout(header=[["author", "A2", "B2"], ["date", "C2", "B2"]]),
    layout(header=[["date", "A2", "A2"]]),
    layout(answers=("Done", "Done", None)), layout(answers=("Done", "Not done", "N/A")),
]

versions = [
    {"workbook": FIXTURE, "layout": STANDARD},
    {"workbook": FIXTURE, "layout": layout(columns=[["id", "C"], ["control", "D"], ["answer", "F"], ["comment", "G"]])},
    {"workbook": FIXTURE, "layout": layout(columns=[["id", "B"], ["control", "C"], ["answer", "F"], ["comment", "G"]])},
    {"workbook": FIXTURE, "layout": layout(columns=[["control", "D"], ["answer", "F"], ["comment", "G"]])},
    {"workbook": FIXTURE, "layout": layout(first=1, last=5)},
    {"workbook": FIXTURE, "layout": layout(sheet_name="Missing")},
    {"workbook": FIXTURE, "layout": layout(first=8, last=9, columns=[
        ["objective", "A"], ["domain", "B"], ["control", "C"], ["answer", "F"], ["comment", "G"]])},
    {"workbook": ID_COLUMN, "layout": layout(columns=[["id", "A"], ["domain", "B"], ["objective", "C"], ["control", "D"],
                                                      ["contact", "E"], ["answer", "G"], ["comment", "H"]])},
    {"workbook": PLAIN, "layout": STANDARD},
]
long_control = fixture()
long_control[SHEET2] = long_control[SHEET2].replace(
    s("C7", 14), '<c r="C7" t="inlineStr"><is><t>' + "c" * 4001 + "</t></is></c>")
LONG = workbook("a control longer than an item holds", package(long_control))
versions.append({"workbook": LONG, "layout": STANDARD})
long_id = fixture()
long_id[SHEET2] = long_id[SHEET2].replace(s("A7", 12), '<c r="A7" t="inlineStr"><is><t>' + "i" * 201 + "</t></is></c>")
LONG_ID = workbook("an id longer than a key holds", package(long_id))
versions.append({"workbook": LONG_ID, "layout": layout(columns=[["id", "A"], ["control", "C"], ["answer", "F"],
                                                                ["comment", "G"]])})

# ---------------------------------------------------------------- statements

ANSWERED = "2026-09-20T08:30:00Z"
SIGNED = "2026-09-29T12:00:00Z"


def answer(id_, value, comment, at=ANSWERED, by="developer", kind="person", carried_by=None, confirm=False):
    return {"id": id_, "value": value, "word": value, "comment": comment, "answeredBy": by, "answeredByKind": kind,
            "answeredAt": at, "carriedFrom": 7 if carried_by else None, "carriedBy": carried_by,
            "carriedAt": ANSWERED if carried_by else None, "needsConfirmation": confirm, "withdrawn": False}


def measured(outcome, reason, summary, purpose="sign_off", as_of="2026-09-28T00:00:00Z"):
    return {"purpose": purpose, "ruleKind": "dependency_analysis", "ruleDigest": "r" * 64, "rule": None,
            "outcome": outcome, "reason": reason, "asOf": as_of, "computedAt": SIGNED, "summary": summary,
            "evidenceDigest": "e" * 64, "evidence": None}


def proof(id_, kind, link=None, file_name=None, sha=None, on="2026-09-01", until=None, withdrawn=None):
    return {"id": id_, "kind": kind, "link": link, "fileName": file_name,
            "mediaType": "application/pdf" if file_name else None, "size": 3 if file_name else None, "sha256": sha,
            "performedOn": on, "validUntil": until, "addedBy": "developer", "addedAt": ANSWERED,
            "withdrawnBy": "developer" if withdrawn else None, "withdrawnAt": withdrawn}


def line(position, row_number, given, measurement=None, reconciliation="not_measured_here", proofs=(), control=None):
    return {"itemId": 100 + position, "key": f"key-{position}", "position": position, "row": row_number,
            "domain": "Domain", "objective": "Objective", "control": control or f"Control {position}",
            "contact": "Contact", "kpi": "", "contentDigest": "d" * 64, "evidenceRequired": "link_or_file",
            "evidenceValidityMonths": None, "answer": given, "history": [given] if given else [],
            "measurement": measurement, "reconciliation": reconciliation, "evidence": list(proofs)}


def statement(workbook_index, signed=True, lines=None, **changes):
    sha = hashlib.sha256(base64.b64decode(workbooks[workbook_index]["xlsx"])).hexdigest()
    lines = lines if lines is not None else [
        line(1, 7, answer(1, "yes", None), proofs=[
            proof(10, "link", link="https://wiki.example.invalid/accounts"),
            proof(11, "link", link="https://wiki.example.invalid/withdrawn", on="2026-08-01", withdrawn=ANSWERED)]),
        line(2, 8, answer(2, "no", "Two service accounts remain & <are> tracked.\u0001")),
        line(3, 9, answer(3, "yes", "The pipeline is not scanned yet.", kind="system", by="Vectispire"),
             measured("no_data", "never_examined", "No repository has been examined."), "declared_not_measured",
             [proof(12, "file", file_name="sessions.pdf", sha="ab" * 32, on="2026-09-10", until="2027-09-10")]),
        line(4, 10, answer(4, "not_applicable", "  ", carried_by="lead", confirm=True),
             measured("pass", None, "2 repositories, SBOM within 7 days.", purpose="read"), "excluded"),
        line(5, 11, None),
    ]
    out = {"form": 2, "status": "signed_off" if signed else "draft", "signed": signed,
           "project": {"id": 42, "name": "Checkout"}, "revision": 3,
           "template": {"slug": "release", "name": "Release checklist", "version": 2, "label": "2026 edition",
                        "sourceSha256": sha},
           "header": {"product": "Checkout <&>", "author": "developer", "date": SIGNED if signed else None},
           "opened": {"by": "developer", "at": "2026-09-18T09:00:00Z"},
           "submitted": {"by": "developer", "at": "2026-09-28T09:00:00.123Z"} if signed else None,
           "signedOff": {"by": "ciso", "at": SIGNED} if signed else None,
           "fourEyesRequired": True if signed else None, "productVersion": "1.2.3",
           "producedAt": SIGNED if signed else "2026-09-29T13:00:00.000456789Z", "lines": lines}
    out.update(changes)
    return out


NA = ("Done", "Not done", "Not relevant")
renders = [
    {"workbook": FIXTURE, "layout": layout(answers=NA), "statement": statement(FIXTURE)},
    {"workbook": FIXTURE, "layout": layout(answers=NA), "statement": statement(FIXTURE, signed=False)},
    {"workbook": FIXTURE, "layout": layout(answers=NA), "statement": statement(
        FIXTURE, signed=False, status="signed_off", signedOff={"by": "ciso", "at": SIGNED}, fourEyesRequired=False,
        productVersion=None)},
    {"workbook": FIXTURE, "layout": layout(answers=NA, header=[]), "statement": statement(FIXTURE)},
    {"workbook": FIXTURE, "layout": layout(answers=NA), "statement": statement(FIXTURE, lines=[])},
    {"workbook": FIXTURE, "layout": layout(answers=NA), "statement": statement(
        FIXTURE, lines=[line(1, 12, answer(1, "yes", None))])},
    {"workbook": FIXTURE, "layout": layout(answers=NA), "statement": statement(
        FIXTURE, lines=[line(1, 7, answer(1, "maybe", None))])},
    {"workbook": FIXTURE, "layout": layout(answers=NA), "statement": statement(
        FIXTURE, template={"slug": "release", "name": "Release checklist", "version": 2, "label": None,
                           "sourceSha256": "0" * 64})},
    {"workbook": FIXTURE, "layout": layout(answers=NA, sheet_name="Nowhere"), "statement": statement(FIXTURE)},
    {"workbook": DATE1904, "layout": layout(answers=NA), "statement": statement(DATE1904)},
    {"workbook": CHAIN, "layout": layout(answers=NA), "statement": statement(CHAIN)},
    {"workbook": CHAIN, "layout": layout(answers=NA, header=[["product", "A3", "B3"]]), "statement": statement(CHAIN)},
    {"workbook": SHARED, "layout": layout(answers=NA), "statement": statement(SHARED)},
    {"workbook": MASTERS, "layout": layout(first=7, last=19, header=[], answers=NA),
     "statement": statement(MASTERS, lines=[line(r - 6, r, answer(r, "yes", None)) for r in range(7, 20)])},
    {"workbook": SPLICED, "layout": layout(answers=NA, header=[["date", "A2", "B2"], ["product", "A4", "D4"],
                                                               ["author", "A5", "B5"]]),
     "statement": statement(SPLICED, lines=[
         line(1, 7, answer(1, "yes", "seven")), line(2, 8, answer(2, "no", "eight")), line(3, 9, answer(3, "no", "nine")),
         line(4, 10, answer(4, "yes", None)), line(5, 11, answer(5, "yes", "eleven"))])},
    {"workbook": EMPTY_DATA, "layout": layout(answers=NA), "statement": statement(EMPTY_DATA)},
    {"workbook": NO_DATA, "layout": layout(answers=NA), "statement": statement(NO_DATA)},
    {"workbook": TAKEN, "layout": layout(answers=NA), "statement": statement(TAKEN)},
    {"workbook": PREFIXED, "layout": layout(answers=NA), "statement": statement(PREFIXED)},
    {"workbook": PREFIXED_BOOK, "layout": layout(answers=NA), "statement": statement(PREFIXED_BOOK)},
    {"workbook": BOM, "layout": layout(answers=NA), "statement": statement(BOM)},
    {"workbook": UTF16_SHEET, "layout": layout(answers=NA), "statement": statement(UTF16_SHEET)},
    {"workbook": LATIN1_SHEET, "layout": layout(answers=NA), "statement": statement(LATIN1_SHEET)},
    {"workbook": STORED_FOLDERS, "layout": layout(answers=NA), "statement": statement(STORED_FOLDERS)},
    {"workbook": SELF_CLOSED, "layout": layout(answers=NA), "statement": statement(SELF_CLOSED)},
    {"workbook": NO_FOLDER, "layout": layout(answers=NA), "statement": statement(NO_FOLDER)},
    {"workbook": HEADERS, "layout": layout(answers=NA), "statement": statement(
        HEADERS, lines=[line(1, 7, answer(1, "yes", "x" * 33_000, at=None))],
        header={"product": "\U0001F600" * 20_000, "author": "a", "date": "1899-12-30T00:00:00Z"})},
    {"workbook": FIXTURE, "layout": layout(answers=NA), "statement": statement(
        FIXTURE, template={"slug": "release", "name": "Release checklist", "version": 2, "label": "  ",
                           "sourceSha256": hashlib.sha256(base64.b64decode(workbooks[FIXTURE]["xlsx"])).hexdigest()})},
]
trials = [
    {"workbook": FIXTURE, "layout": STANDARD},
    {"workbook": SHARED, "layout": STANDARD},
    {"workbook": FIXTURE, "layout": layout(answers=NA)},
    {"workbook": ID_COLUMN, "layout": layout(columns=[["id", "A"], ["domain", "B"], ["objective", "C"], ["control", "D"],
                                                      ["contact", "E"], ["answer", "G"], ["comment", "H"]])},
]

statements = [statement(FIXTURE), statement(FIXTURE, signed=False), statement(FIXTURE, lines=[]),
              statement(FIXTURE, signed=True, signedOff=None)]

serials = [{"instant": instant, "date1904": date1904} for instant in [
    "2026-09-29T12:00:00Z", "2026-09-29T00:00:00Z", "2026-09-29T23:59:59Z", "2026-09-29T00:00:01Z",
    "2026-09-29T08:00:00.999Z", "1900-03-01T00:00:00Z", "1899-12-30T00:00:00Z", "1899-12-29T18:00:00Z",
    "1904-01-01T00:00:00Z", "1903-12-31T06:00:00Z", "1970-01-01T00:00:00Z", "9999-12-31T23:59:59Z",
    "1980-02-01T00:00:00Z", "2000-01-01T00:00:03Z", "2000-01-01T00:00:27Z", "2000-01-01T00:01:21Z"]
    for date1904 in (False, True)]

zips = [
    [{"name": "a.txt", "bytes": base64.b64encode(b"hello").decode(), "stored": False, "directory": False}],
    [{"name": "dir/", "bytes": "", "stored": True, "directory": True},
     {"name": "dir/stored.bin", "bytes": base64.b64encode(noise(3000)).decode(), "stored": True, "directory": False},
     {"name": "dir/deflated.xml", "bytes": base64.b64encode(("<x>" + "abc" * 5000 + "</x>").encode()).decode(),
      "stored": False, "directory": False},
     {"name": "naïve €.txt", "bytes": "", "stored": False, "directory": False},
     {"name": "big.bin", "bytes": base64.b64encode(noise(20_000, 7) + b"\0" * 100_000).decode(), "stored": False,
      "directory": False}],
    [],
]

json.dump({"workbooks": workbooks, "layouts": layouts, "versions": versions, "renders": renders, "trials": trials,
           "statements": statements, "serials": serials, "zips": zips},
          open(sys.argv[1], "w", encoding="utf-8"), ensure_ascii=False, indent=1)
open(sys.argv[1], "a", encoding="utf-8").write("\n")
