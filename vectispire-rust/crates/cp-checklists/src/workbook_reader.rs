//! `WorkbookReader`: an `.xlsx` package read into a [`Workbook`] from its parts, with no spreadsheet library.
//!
//! **The zip and its guards** are checked as the entries are read, never from what the archive says of itself: at
//! most `max_entries` entries; each inflated to at most `max_entry_bytes` and all of them to `max_inflated_bytes`,
//! counted as the bytes come out of the inflater; an entry inflating more than `max_ratio` times the compressed
//! bytes the inflater consumed, once past a small grace, is refused. Every entry is read through that counter, the
//! ones not kept too. An archive inside the archive — by its name or its first four bytes — is refused, and so is a
//! part name the archive holds twice.
//!
//! **Refused before a cell is read**: a legacy `.xls` (and an encrypted `.xlsx`), an OpenDocument spreadsheet, a
//! binary `.xlsb`, a macro-enabled workbook, a package without a workbook part (decision 0032 §11), and any
//! relationship whose target is external (§3): the renderer copies the package into a document the platform signs.
//!
//! **The XML** goes through [`safe_xml`], a DOCTYPE refused outright; one element budget spans every part read, so
//! the parts are read in Java's order and as many times as Java reads them.

use std::collections::{BTreeMap, HashSet};

use vectispire_domain::bounded_text::clip;
use vectispire_domain::checklists::Defect;
use vectispire_domain::java;

use crate::cell::{CellRange, CellRef, CellValue, ListValidation};
use crate::safe_xml::{self, Budget, Element, Handler};
use crate::workbook::{Limits, Sheet, Workbook};
use crate::zip_input::{DEFLATED, STORED, ZipError, ZipInput};
use crate::{Failure, Refused, refused, sha256_hex_bytes};

/// What reading a workbook raises: the importer's refusal, or the defect Java leaves uncaught (a zip header past
/// the 65,535 bytes `ZipEntry` accepts, an `IllegalArgumentException`).
pub type ReadFailure = Failure;

/// Excel's own ceiling on a cell's text; longer was not written by Excel.
pub const MAX_CELL_TEXT: usize = 32_767;

const COMPOUND_FILE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const ARCHIVE_SUFFIXES: [&str; 18] = [
    ".zip", ".jar", ".gz", ".tgz", ".tar", ".7z", ".rar", ".xlsx", ".xlsm", ".xlsb", ".xltx", ".xltm", ".docx",
    ".docm", ".pptx", ".pptm", ".ods", ".odt",
];
const MAIN_SHEET: &str = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml";
const MAIN_TEMPLATE: &str = "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml";
const READ_BUFFER: usize = 8_192;

/// `Workbook.read(file, maxBytes, limits)`.
pub(crate) fn read(file: &[u8], max_bytes: i64, limits: Limits) -> Result<Workbook, Failure> {
    require_zip(file, max_bytes)?;
    let mut reader = Reader { limits, budget: Budget::new(limits.max_elements, "The workbook") };
    let parts = reader.unzip(file)?;
    reader.workbook_of(file, &parts).map_err(Failure::from)
}

/// An entry of a package as the archive holds it, under the name the archive gives it; `stored` when it was not
/// compressed. What the renderer copies (decision 0032 §10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageEntry {
    pub name: String,
    pub bytes: Vec<u8>,
    pub directory: bool,
    pub stored: bool,
}

/// `WorkbookReader.entries`: every entry in the archive's order, its bytes whole, read through the same guards as
/// [`read`] — the renderer takes the stored template, which passed them at its import, and holds it to them again.
pub fn entries(file: &[u8], max_bytes: i64, limits: Limits) -> Result<Vec<PackageEntry>, Failure> {
    require_zip(file, max_bytes)?;
    let reader = Reader { limits, budget: Budget::new(limits.max_elements, "The workbook") };
    let mut entries = Vec::new();
    reader.walk(file, true, &mut |name, bytes, directory, method| {
        entries.push(PackageEntry { name: name.to_owned(), bytes, directory, stored: method == STORED });
    })?;
    Ok(entries)
}

fn require_zip(file: &[u8], max_bytes: i64) -> Result<(), Refused> {
    if file.is_empty() {
        return Err(refused("The workbook is empty."));
    }
    if i64::try_from(file.len()).unwrap_or(i64::MAX) > max_bytes {
        return Err(refused(format!("The workbook is larger than the {max_bytes} bytes accepted.")));
    }
    if file.starts_with(&COMPOUND_FILE) {
        return Err(refused(
            "This is a legacy .xls workbook, or an encrypted one: only an .xlsx without a password is read. Save it \
             as an Excel workbook (.xlsx) and import it again.",
        ));
    }
    if !file.starts_with(b"PK\x03\x04") {
        return Err(refused("The file is not an .xlsx workbook."));
    }
    Ok(())
}

fn macro_enabled() -> Refused {
    refused(
        "This workbook carries macros: a template is read without them. Save it as an Excel workbook (.xlsx) and \
         import it again.",
    )
}

fn nested(name: &str) -> Refused {
    refused(format!("Entry {name} is an archive inside the workbook; nested archives are not opened."))
}

/// A part: its name as the index keys it, and its bytes (empty for a part nobody parses).
struct Part {
    name: String,
    bytes: Vec<u8>,
}

/// The package's parts by normalised name, in the archive's order.
struct Parts(Vec<Part>);

impl Parts {
    fn get(&self, name: &str) -> Option<&Part> {
        self.0.iter().find(|part| part.name == name)
    }

    fn required(&self, name: &str) -> Result<&Part, Refused> {
        self.get(name).ok_or_else(|| {
            refused(format!(
                "The workbook refers to part {}, which the package does not hold.",
                clip(Some(name), 120).unwrap_or("")
            ))
        })
    }
}

#[derive(Debug, Clone)]
struct Relationship {
    id: String,
    kind: String,
    target: String,
}

struct ContentTypes {
    defaults: Vec<(String, String)>,
    overrides: Vec<(String, String)>,
}

impl ContentTypes {
    /// The part's content type, lower-cased; empty when the package states none.
    fn of(&self, part: &str) -> String {
        if let Some((_, kind)) = self.overrides.iter().find(|(name, _)| name == part) {
            return kind.clone();
        }
        let Some(dot) = part.rfind('.') else {
            return String::new();
        };
        let extension = part.get(dot.saturating_add(1)..).unwrap_or_default();
        self.defaults.iter().find(|(name, _)| name == extension).map(|(_, kind)| kind.clone()).unwrap_or_default()
    }
}

/// `HashMap.put`: a key put again keeps its place and takes the new value.
fn put(map: &mut Vec<(String, String)>, key: String, value: String) {
    match map.iter_mut().find(|(existing, _)| *existing == key) {
        Some(entry) => entry.1 = value,
        None => map.push((key, value)),
    }
}

struct Reader {
    limits: Limits,
    budget: Budget,
}

impl Reader {
    fn unzip(&self, file: &[u8]) -> Result<Parts, Failure> {
        let mut parts = Vec::new();
        self.walk(file, false, &mut |name, bytes, directory, _| {
            if !directory {
                let key = normalized_name(clip(Some(name), 200).unwrap_or(""));
                parts.push(Part { name: key, bytes });
            }
        })?;
        Ok(Parts(parts))
    }

    /// Walks the archive through the guards, handing each entry on: its bytes when it is kept — every entry with
    /// `keep_all`, only the parts the reader parses otherwise.
    fn walk(&self, file: &[u8], keep_all: bool, sink: &mut Sink<'_>) -> Result<(), Failure> {
        let mut zip = ZipInput::new(file);
        let mut seen: HashSet<String> = HashSet::new();
        let mut inflated: i64 = 0;
        let mut entries: i64 = 0;
        let outcome = (|| -> Result<(), WalkStop> {
            while let Some(entry) = zip.next_entry()? {
                entries = entries.saturating_add(1);
                if entries > i64::from(self.limits.max_entries) {
                    return Err(refused(format!(
                        "The workbook's zip holds more than {} entries.",
                        self.limits.max_entries
                    ))
                    .into());
                }
                let name = clip(Some(&entry.name), 200).unwrap_or("").to_owned();
                let key = normalized_name(&name);
                if !seen.insert(key.clone()) {
                    return Err(refused(format!(
                        "The workbook's zip holds {name} twice; two programs could each read a different one."
                    ))
                    .into());
                }
                if ARCHIVE_SUFFIXES.iter().any(|suffix| key.ends_with(suffix)) {
                    return Err(nested(&name).into());
                }
                if entry.is_directory() {
                    sink(&entry.name, Vec::new(), true, entry.method);
                    continue;
                }
                let keep = keep_all || key.ends_with(".xml") || key.ends_with(".rels") || key == "mimetype";
                let bytes = self.drain(&mut zip, entry.method, &name, keep, &mut inflated)?;
                sink(&entry.name, bytes, false, entry.method);
            }
            Ok(())
        })();
        match outcome {
            Ok(()) => {}
            Err(WalkStop::Refused(refusal)) => return Err(refusal.into()),
            Err(WalkStop::Zip(ZipError::Malformed)) => {
                return Err(refused("The workbook is not a readable zip archive.").into());
            }
            Err(WalkStop::Zip(ZipError::Truncated)) => {
                return Err(refused("The workbook's zip could not be read to its end.").into());
            }
            Err(WalkStop::Zip(ZipError::Illegal(message))) => return Err(Defect(message.to_owned()).into()),
        }
        if entries == 0 {
            return Err(refused("The workbook is an empty zip archive.").into());
        }
        Ok(())
    }

    /// One entry inflated through the counters, kept or discarded: its bytes when kept, nothing otherwise.
    fn drain(
        &self,
        zip: &mut ZipInput<'_>,
        method: u16,
        name: &str,
        keep: bool,
        inflated: &mut i64,
    ) -> Result<Vec<u8>, WalkStop> {
        let mut kept = Vec::new();
        let mut head: Vec<u8> = Vec::with_capacity(4);
        let mut read: i64 = 0;
        let mut buffer = vec![0u8; READ_BUFFER];
        loop {
            let n = zip.read(&mut buffer)?;
            if n <= 0 {
                break;
            }
            let length = usize::try_from(n).unwrap_or(0);
            let chunk = buffer.get(..length).unwrap_or_default();
            for &byte in chunk.iter().take(4usize.saturating_sub(head.len())) {
                head.push(byte);
            }
            read = read.saturating_add(n);
            *inflated = inflated.saturating_add(n);
            if read > self.limits.max_entry_bytes {
                return Err(
                    refused(format!("Entry {name} inflates past {} bytes.", self.limits.max_entry_bytes)).into()
                );
            }
            if *inflated > self.limits.max_inflated_bytes {
                return Err(
                    refused(format!("The workbook inflates past {} bytes.", self.limits.max_inflated_bytes)).into()
                );
            }
            let compressed = i64::try_from(zip.compressed_read()).unwrap_or(i64::MAX).max(1);
            if method == DEFLATED
                && read > self.limits.ratio_grace_bytes
                && read > i64::from(self.limits.max_ratio).saturating_mul(compressed)
            {
                return Err(refused(format!(
                    "Entry {name} inflates more than {} times its compressed size, as a zip bomb does.",
                    self.limits.max_ratio
                ))
                .into());
            }
            if keep {
                kept.extend_from_slice(chunk);
            }
        }
        if head == b"PK\x03\x04" {
            return Err(nested(name).into());
        }
        Ok(if keep { kept } else { Vec::new() })
    }

    fn workbook_of(&mut self, file: &[u8], parts: &Parts) -> Result<Workbook, Refused> {
        if let Some(mimetype) = parts.get("mimetype")
            && mimetype.bytes.starts_with(b"application/vnd.oasis.opendocument")
        {
            return Err(refused(
                "This is an OpenDocument spreadsheet (.ods): only an .xlsx workbook is read. Save it as an Excel \
                 workbook (.xlsx) and import it again.",
            ));
        }
        let types = self.content_types(parts)?;
        for part in &parts.0 {
            let kind = types.of(&part.name);
            if java::to_lower_root(&part.name).ends_with("vbaproject.bin")
                || kind.contains("vbaproject")
                || kind.contains("macrosheet")
            {
                return Err(macro_enabled());
            }
        }
        for part in &parts.0 {
            if java::to_lower_root(&part.name).ends_with(".rels") {
                self.relationships_in(part)?;
            }
        }

        let main = self
            .relationships("", parts)?
            .into_iter()
            .find(|relationship| relationship.kind.ends_with("/officeDocument"))
            .ok_or_else(|| refused("The package holds no workbook part: is it an .xlsx?"))?;
        let workbook_type = types.of(&main.target);
        if workbook_type.contains("binary") {
            return Err(refused("This is a binary workbook (.xlsb): only an .xlsx workbook is read."));
        }
        if workbook_type.contains("macroenabled") {
            return Err(macro_enabled());
        }
        if workbook_type != MAIN_SHEET && workbook_type != MAIN_TEMPLATE {
            return Err(refused("The package's main part is not a spreadsheet: is it an .xlsx?"));
        }
        let workbook_part = parts.required(&main.target)?;

        let mut entries: Vec<(String, String)> = Vec::new();
        let mut defined_names: Vec<(String, String)> = Vec::new();
        self.workbook(workbook_part, &mut entries, &mut defined_names)?;

        let mut links: Vec<(String, Relationship)> = Vec::new();
        for relationship in self.relationships(&workbook_part.name, parts)? {
            match links.iter_mut().find(|(id, _)| *id == relationship.id) {
                Some(link) => link.1 = relationship,
                None => links.push((relationship.id.clone(), relationship)),
            }
        }
        // `HashMap.values()` decides which of two shared-strings relationships is read: its order, not the file's.
        let strings = match java_hash_order(&links).into_iter().find(|link| link.kind.ends_with("/sharedStrings")) {
            Some(link) => {
                let part = parts.required(&link.target)?;
                self.shared_strings(part)?
            }
            None => Vec::new(),
        };

        let mut sheets = Vec::new();
        let mut names: HashSet<String> = HashSet::new();
        let mut cells: i32 = 0;
        for (name, relationship) in &entries {
            let Some((_, link)) = links.iter().find(|(id, _)| id == relationship) else {
                return Err(refused(format!("Sheet \"{name}\" points at no part of the package.")));
            };
            if !link.kind.ends_with("/worksheet") {
                // A chart sheet holds no cells, and no checklist lives on one.
                continue;
            }
            if !names.insert(java::to_lower_root(name)) {
                return Err(refused(format!("The workbook names two sheets \"{name}\".")));
            }
            let part = parts.required(&link.target)?;
            sheets.push(self.worksheet(name, part, &strings, &mut cells)?);
        }
        if sheets.is_empty() {
            return Err(refused("The workbook holds no worksheet."));
        }
        Ok(Workbook { sha256: sha256_hex_bytes(file), sheets, defined_names })
    }

    fn read_part(&mut self, part: &Part, handler: &mut dyn Handler) -> Result<(), Refused> {
        safe_xml::read(&part.bytes, &format!("Part {}", part.name), &mut self.budget, handler)
    }

    fn content_types(&mut self, parts: &Parts) -> Result<ContentTypes, Refused> {
        let part = parts
            .get("[content_types].xml")
            .ok_or_else(|| refused("The package states no content types: it is not an Office Open XML workbook."))?;
        let mut types = ContentTypes { defaults: Vec::new(), overrides: Vec::new() };
        self.read_part(
            part,
            &mut Starts(|element: &Element<'_>| {
                let Some(kind) = element.attribute("ContentType") else {
                    return Ok(());
                };
                let lower = java::to_lower_root(java::strip(kind));
                if element.name == "Default" && element.attribute("Extension").is_some() {
                    let extension = java::to_lower_root(java::strip(element.attribute("Extension").unwrap_or("")));
                    put(&mut types.defaults, extension, lower);
                } else if element.name == "Override"
                    && let Some(part_name) = element.attribute("PartName")
                {
                    put(&mut types.overrides, normalized_name(part_name), lower);
                }
                Ok(())
            }),
        )?;
        Ok(types)
    }

    /// The relationships of a part — `""` for the package's own — their targets resolved to part names.
    fn relationships(&mut self, source: &str, parts: &Parts) -> Result<Vec<Relationship>, Refused> {
        match parts.get(&relationships_of(source)) {
            Some(part) => self.relationships_in(part),
            None if source.is_empty() => {
                Err(refused("The package holds no relationships part: it is not an .xlsx workbook."))
            }
            None => Ok(Vec::new()),
        }
    }

    fn relationships_in(&mut self, part: &Part) -> Result<Vec<Relationship>, Refused> {
        let owner = owner_of(&part.name);
        let part_name = part.name.clone();
        let mut found = Vec::new();
        self.read_part(
            part,
            &mut Starts(|element: &Element<'_>| {
                if element.name != "Relationship" {
                    return Ok(());
                }
                let target = element.attribute("Target");
                // `"external".equalsIgnoreCase(…)`: no character outside ASCII folds to one of these letters.
                if java::strip(element.attribute("TargetMode").unwrap_or("null")).eq_ignore_ascii_case("external") {
                    return Err(refused(format!(
                        "Part {part_name} points outside the package, at \"{}\"; a template with an external link \
                         is not imported, because the document rendered from it is signed.",
                        clip(Some(target.unwrap_or("null")), 120).unwrap_or("")
                    )));
                }
                if let (Some(target), Some(kind)) = (target, element.attribute("Type")) {
                    found.push(Relationship {
                        id: element.attribute("Id").unwrap_or("null").to_owned(),
                        kind: java::strip(kind).to_owned(),
                        target: resolve(&owner, java::strip(target)),
                    });
                }
                Ok(())
            }),
        )?;
        Ok(found)
    }

    fn workbook(
        &mut self,
        part: &Part,
        sheets: &mut Vec<(String, String)>,
        defined_names: &mut Vec<(String, String)>,
    ) -> Result<(), Refused> {
        struct Book<'a> {
            limits: Limits,
            sheets: &'a mut Vec<(String, String)>,
            defined_names: &'a mut Vec<(String, String)>,
            name: Option<String>,
            formula: String,
        }
        impl Handler for Book<'_> {
            fn start(&mut self, element: &Element<'_>) -> Result<(), Refused> {
                match element.name {
                    "sheet" => {
                        let (Some(sheet), Some(id)) = (element.attribute("name"), element.attribute("id")) else {
                            return Err(refused("The workbook lists a sheet without a name or a part."));
                        };
                        if i64::try_from(self.sheets.len()).unwrap_or(i64::MAX) == i64::from(self.limits.max_sheets) {
                            return Err(refused(format!(
                                "The workbook holds more than {} sheets.",
                                self.limits.max_sheets
                            )));
                        }
                        self.sheets.push((sheet.to_owned(), id.to_owned()));
                    }
                    "definedName" => {
                        // A name scoped to one sheet means something else on every other: only the workbook's own.
                        self.name = match element.attribute("localSheetId") {
                            None => element.attribute("name").map(str::to_owned),
                            Some(_) => None,
                        };
                        self.formula.clear();
                    }
                    _ => {}
                }
                Ok(())
            }

            fn text(&mut self, characters: &str) -> Result<(), Refused> {
                if self.name.is_some() {
                    append(&mut self.formula, characters, "A defined name")?;
                }
                Ok(())
            }

            fn end(&mut self, element: &str) -> Result<(), Refused> {
                if element == "definedName"
                    && let Some(name) = self.name.take()
                {
                    put(self.defined_names, name, java::strip(&self.formula).to_owned());
                }
                Ok(())
            }
        }
        let limits = self.limits;
        self.read_part(part, &mut Book { limits, sheets, defined_names, name: None, formula: String::new() })
    }

    fn shared_strings(&mut self, part: &Part) -> Result<Vec<String>, Refused> {
        struct Strings {
            max: i32,
            strings: Vec<String>,
            open: Vec<String>,
            current: String,
        }
        impl Handler for Strings {
            fn start(&mut self, element: &Element<'_>) -> Result<(), Refused> {
                self.open.push(element.name.to_owned());
                if element.name == "si" {
                    if i64::try_from(self.strings.len()).unwrap_or(i64::MAX) == i64::from(self.max) {
                        return Err(refused(format!(
                            "The workbook's shared strings hold more than {} entries.",
                            self.max
                        )));
                    }
                    self.current.clear();
                }
                Ok(())
            }

            fn text(&mut self, characters: &str) -> Result<(), Refused> {
                // A string's text is its t elements, directly or in a run — never a phonetic reading (rPh).
                if self.open.last().is_some_and(|name| name == "t") && !self.open.iter().any(|name| name == "rPh") {
                    append(&mut self.current, characters, "A shared string")?;
                }
                Ok(())
            }

            fn end(&mut self, element: &str) -> Result<(), Refused> {
                self.open.pop();
                if element == "si" {
                    self.strings.push(self.current.clone());
                }
                Ok(())
            }
        }
        let mut strings = Strings {
            max: self.limits.max_shared_strings,
            strings: Vec::new(),
            open: Vec::new(),
            current: String::new(),
        };
        self.read_part(part, &mut strings)?;
        Ok(strings.strings)
    }

    fn worksheet(
        &mut self,
        name: &str,
        part: &Part,
        strings: &[String],
        cell_count: &mut i32,
    ) -> Result<Sheet, Refused> {
        let mut handler = Worksheet {
            what: format!("Sheet \"{name}\""),
            strings,
            max_cells: self.limits.max_cells,
            cell_count,
            cells: BTreeMap::new(),
            merged: Vec::new(),
            validations: Vec::new(),
            open: Vec::new(),
            row: 0,
            column: 0,
            cell: None,
            kind: None,
            has_value: false,
            has_formula: false,
            value: String::new(),
            formula: String::new(),
            inline: String::new(),
            validation_type: None,
            validation_ranges: None,
            validation_formula: String::new(),
            validation_sqref: String::new(),
        };
        self.read_part(part, &mut handler)?;
        Ok(Sheet {
            name: name.to_owned(),
            cells: handler.cells,
            merged: handler.merged,
            validations: handler.validations,
        })
    }
}

/// Where a walk hands each entry: its name as the archive gives it, its bytes, whether it is a directory, its method.
type Sink<'a> = dyn FnMut(&str, Vec<u8>, bool, u16) + 'a;

/// Why a walk stopped: a guard, or the zip stream.
enum WalkStop {
    Refused(Refused),
    Zip(ZipError),
}

impl From<Refused> for WalkStop {
    fn from(refusal: Refused) -> WalkStop {
        WalkStop::Refused(refusal)
    }
}

impl From<ZipError> for WalkStop {
    fn from(error: ZipError) -> WalkStop {
        WalkStop::Zip(error)
    }
}

/// A handler that only looks at elements as they start.
struct Starts<F>(F);

impl<F: FnMut(&Element<'_>) -> Result<(), Refused>> Handler for Starts<F> {
    fn start(&mut self, element: &Element<'_>) -> Result<(), Refused> {
        (self.0)(element)
    }
}

struct Worksheet<'a> {
    what: String,
    strings: &'a [String],
    max_cells: i32,
    cell_count: &'a mut i32,
    cells: BTreeMap<CellRef, CellValue>,
    merged: Vec<CellRange>,
    validations: Vec<ListValidation>,
    open: Vec<String>,
    row: i32,
    column: i32,
    cell: Option<CellRef>,
    kind: Option<String>,
    has_value: bool,
    has_formula: bool,
    value: String,
    formula: String,
    inline: String,
    validation_type: Option<String>,
    validation_ranges: Option<String>,
    validation_formula: String,
    validation_sqref: String,
}

impl Worksheet<'_> {
    fn opened(&self, name: &str) -> bool {
        self.open.iter().any(|open| open == name)
    }

    fn cell_what(&self, cell: CellRef) -> String {
        format!("{}, cell {cell},", self.what)
    }

    fn decode(&self, cell: CellRef) -> Result<Option<CellValue>, Refused> {
        let literal = self.value.as_str();
        if self.has_formula {
            let cached = self.has_value.then(|| {
                if self.kind.as_deref() == Some("b") { bool_of(literal).text().to_owned() } else { literal.to_owned() }
            });
            return Ok(Some(CellValue::Formula { expression: java::strip(&self.formula).to_owned(), cached }));
        }
        Ok(match self.kind.as_deref().unwrap_or("n") {
            "s" => {
                if !self.has_value {
                    return Ok(None);
                }
                let index = shared_index(java::strip(literal));
                let Some(string) = index.and_then(|index| self.strings.get(index)) else {
                    return Err(refused(format!(
                        "{}, cell {cell} refers to a shared string the workbook does not hold.",
                        self.what
                    )));
                };
                text_value(string)
            }
            "inlineStr" => text_value(&self.inline),
            "str" | "d" => {
                if self.has_value {
                    text_value(literal)
                } else {
                    None
                }
            }
            "b" => self.has_value.then(|| bool_of(literal)),
            "e" => self.has_value.then(|| CellValue::Error(java::strip(literal).to_owned())),
            _ => (!java::is_blank(literal)).then(|| CellValue::Number(java::strip(literal).to_owned())),
        })
    }
}

impl Handler for Worksheet<'_> {
    fn start(&mut self, element: &Element<'_>) -> Result<(), Refused> {
        let parent = self.open.last().cloned();
        let parent = parent.as_deref();
        self.open.push(element.name.to_owned());
        match element.name {
            "row" if parent == Some("sheetData") => {
                self.row = match element.attribute("r") {
                    None => self.row.saturating_add(1),
                    Some(r) => row_number(r, &self.what)?,
                };
                self.column = 0;
            }
            "c" if parent == Some("row") => {
                let cell = match element.attribute("r") {
                    None => implied(self.row, self.column.saturating_add(1), &self.what)?,
                    Some(r) => CellRef::parse(Some(r)).ok_or_else(|| {
                        refused(format!(
                            "{} has a cell at \"{}\", which is no cell reference.",
                            self.what,
                            clip(Some(r), 20).unwrap_or("")
                        ))
                    })?,
                };
                self.column = cell.column();
                self.cell = Some(cell);
                self.kind = element.attribute("t").map(str::to_owned);
                self.has_value = false;
                self.has_formula = false;
                self.value.clear();
                self.formula.clear();
                self.inline.clear();
            }
            "v" => self.has_value |= parent == Some("c"),
            "f" => self.has_formula |= parent == Some("c"),
            "mergeCell" if parent == Some("mergeCells") => {
                if let Some(range) = CellRange::parse(element.attribute("ref")) {
                    self.merged.push(range);
                }
            }
            "dataValidation" if parent == Some("dataValidations") => {
                self.validation_type = element.attribute("type").map(str::to_owned);
                // The sheet's own list carries its range as an attribute; the extension's in an element (xm:sqref).
                self.validation_ranges =
                    if self.opened("ext") { None } else { element.attribute("sqref").map(str::to_owned) };
                self.validation_formula.clear();
                self.validation_sqref.clear();
            }
            _ => {}
        }
        Ok(())
    }

    fn text(&mut self, characters: &str) -> Result<(), Refused> {
        let current = self.open.last().map(String::as_str);
        let parent = if self.open.len() > 1 { self.open.iter().rev().nth(1).map(String::as_str) } else { Some("") };
        if let Some(cell) = self.cell {
            if current == Some("v") && parent == Some("c") {
                let what = self.cell_what(cell);
                return append(&mut self.value, characters, &what);
            }
            if current == Some("f") && parent == Some("c") {
                let what = self.cell_what(cell);
                return append(&mut self.formula, characters, &what);
            }
            if current == Some("t") && self.opened("is") && !self.opened("rPh") {
                let what = self.cell_what(cell);
                return append(&mut self.inline, characters, &what);
            }
        }
        if self.validation_type.is_some() && self.opened("dataValidation") {
            if self.opened("formula1") && (current == Some("formula1") || current == Some("f")) {
                let what = format!("{}'s validation list", self.what);
                return append(&mut self.validation_formula, characters, &what);
            }
            if current == Some("sqref") {
                let what = format!("{}'s validation range", self.what);
                return append(&mut self.validation_sqref, characters, &what);
            }
        }
        Ok(())
    }

    fn end(&mut self, element: &str) -> Result<(), Refused> {
        self.open.pop();
        let parent = self.open.last().map(String::as_str);
        if element == "c"
            && parent == Some("row")
            && let Some(cell) = self.cell
        {
            if let Some(decoded) = self.decode(cell)?
                && self.cells.insert(cell, decoded).is_none()
            {
                *self.cell_count = self.cell_count.saturating_add(1);
                if *self.cell_count > self.max_cells {
                    return Err(refused(format!(
                        "The workbook holds more than {} cells with a value.",
                        self.max_cells
                    )));
                }
            }
            self.cell = None;
        } else if element == "dataValidation" && parent == Some("dataValidations") && self.validation_type.is_some() {
            if self.validation_type.as_deref() == Some("list") {
                let ranges = self.validation_ranges.clone().unwrap_or_else(|| self.validation_sqref.clone());
                let covered = CellRange::parse_list(Some(&ranges));
                if !covered.is_empty() {
                    self.validations.push(ListValidation {
                        ranges: covered,
                        source: java::strip(&self.validation_formula).to_owned(),
                        from_extension: self.opened("ext"),
                    });
                }
            }
            self.validation_type = None;
        }
        Ok(())
    }
}

fn text_value(text: &str) -> Option<CellValue> {
    (!text.is_empty()).then(|| CellValue::Text(text.to_owned()))
}

/// `"1"` or `"true"` in any case; anything else is false. No character outside ASCII folds to these letters.
fn bool_of(literal: &str) -> CellValue {
    let stripped = java::strip(literal);
    CellValue::Bool(stripped == "1" || stripped.eq_ignore_ascii_case("true"))
}

fn shared_index(literal: &str) -> Option<usize> {
    if literal.is_empty() || literal.len() > 9 || !literal.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    literal.parse().ok()
}

fn row_number(literal: &str, what: &str) -> Result<i32, Refused> {
    let digits = java::strip(literal);
    let number = (!digits.is_empty() && digits.len() <= 7 && digits.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| digits.parse::<i32>().ok())
        .flatten()
        .filter(|number| (1..=CellRef::MAX_ROW).contains(number));
    number.ok_or_else(|| refused(format!("{what} numbers a row \"{}\".", clip(Some(digits), 20).unwrap_or(""))))
}

/// A cell the file places by its order alone, which the format allows.
fn implied(row: i32, column: i32, what: &str) -> Result<CellRef, Refused> {
    if row < 1 || column > CellRef::MAX_COLUMN {
        return Err(refused(format!("{what} has a cell outside any row.")));
    }
    CellRef::new(column, row)
}

fn append(into: &mut String, characters: &str, what: &str) -> Result<(), Refused> {
    if java::utf16_len(into).saturating_add(java::utf16_len(characters)) > MAX_CELL_TEXT {
        return Err(refused(format!(
            "{what} holds more than {MAX_CELL_TEXT} characters, which is more than a spreadsheet cell holds."
        )));
    }
    into.push_str(characters);
    Ok(())
}

/// A part name as the package's index keys it: no leading slash, percent-escapes decoded, lower case.
pub(crate) fn normalized_name(name: &str) -> String {
    let stripped = java::strip(name).trim_start_matches('/');
    java::to_lower_root(&percent_decoded(stripped))
}

/// `xl/workbook.xml` → `xl/_rels/workbook.xml.rels`; `""` → `_rels/.rels`.
pub(crate) fn relationships_of(part: &str) -> String {
    let (folder, name) = part.rsplit_once('/').map_or(("", part), |(folder, name)| (folder, name));
    let folder = if part.contains('/') { format!("{folder}/") } else { String::new() };
    format!("{folder}_rels/{name}.rels")
}

/// The part a relationships part describes: `xl/_rels/workbook.xml.rels` → `xl/workbook.xml`.
fn owner_of(relationships_part: &str) -> String {
    let without = relationships_part.strip_suffix(".rels").unwrap_or(relationships_part);
    // `replaceFirst("(^|/)_rels/", "$1")`: the earliest `_rels/` at the start or after a slash.
    if let Some(rest) = without.strip_prefix("_rels/") {
        return rest.to_owned();
    }
    match without.split_once("/_rels/") {
        Some((before, after)) => format!("{before}/{after}"),
        None => without.to_owned(),
    }
}

/// A relationship's target, relative to its source part's folder unless it starts at the root.
pub(crate) fn resolve(source: &str, target: &str) -> String {
    let path = if target.starts_with('/') {
        target.to_owned()
    } else {
        let folder = source.rsplit_once('/').map_or("", |(folder, _)| folder);
        if source.contains('/') { format!("{folder}/{target}") } else { target.to_owned() }
    };
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            _ => segments.push(segment),
        }
    }
    normalized_name(&segments.join("/"))
}

/// `%XX` escapes decoded to bytes, the rest kept, the whole read back as UTF-8 with replacement characters. A hex
/// digit is what `Character.digit(c, 16)` takes: any decimal digit, and the Latin letters in their two widths.
fn percent_decoded(name: &str) -> String {
    if !name.contains('%') {
        return name.to_owned();
    }
    let mut bytes: Vec<u8> = Vec::new();
    let mut chars = name.chars().peekable();
    while let Some(c) = chars.next() {
        let mut ahead = chars.clone();
        let pair = (ahead.next().and_then(hex), ahead.next().and_then(hex));
        if let ('%', (Some(high), Some(low))) = (c, pair) {
            bytes.push(u8::try_from(high.saturating_mul(16).saturating_add(low)).unwrap_or(0));
            chars.next();
            chars.next();
        } else {
            let mut encoded = [0u8; 4];
            bytes.extend_from_slice(c.encode_utf8(&mut encoded).as_bytes());
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// `Character.digit(c, 16)`: any decimal digit `Character.digit` knows, and a to f in either case and either width.
pub(crate) fn hex(c: char) -> Option<u32> {
    if let Some(digit) = java::digit(c) {
        return Some(digit);
    }
    let from = match c {
        'a'..='f' => u32::from('a'),
        'A'..='F' => u32::from('A'),
        '\u{FF41}'..='\u{FF46}' => 0xFF41,
        '\u{FF21}'..='\u{FF26}' => 0xFF21,
        _ => return None,
    };
    u32::from(c).checked_sub(from).map(|offset| offset.saturating_add(10))
}

/// The values of a `HashMap<String, V>` in the order Java iterates them: by bucket — `String.hashCode` spread by
/// `h ^ h >>> 16`, masked by the table's capacity (16, doubled past three quarters full) — then in insertion order.
fn java_hash_order<V>(entries: &[(String, V)]) -> Vec<&V> {
    let mut capacity: usize = 16;
    while entries.len() > capacity.saturating_div(4).saturating_mul(3) {
        capacity = capacity.saturating_mul(2);
    }
    let bucket = |key: &str| {
        let hash = key.encode_utf16().fold(0i32, |hash, unit| hash.wrapping_mul(31).wrapping_add(i32::from(unit)));
        let spread = (hash ^ ((hash as u32) >> 16) as i32) as u32;
        usize::try_from(spread).unwrap_or(0) & capacity.saturating_sub(1)
    };
    let mut ordered: Vec<(usize, usize, &V)> =
        entries.iter().enumerate().map(|(index, (key, value))| (bucket(key), index, value)).collect();
    ordered.sort_by_key(|(bucket, index, _)| (*bucket, *index));
    ordered.into_iter().map(|(_, _, value)| value).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn part_names_are_keyed_as_the_package_index_keys_them() {
        assert_eq!(normalized_name(" /Xl/Work%20Book.XML"), "xl/work book.xml");
        assert_eq!(relationships_of(""), "_rels/.rels");
        assert_eq!(relationships_of("xl/workbook.xml"), "xl/_rels/workbook.xml.rels");
        assert_eq!(owner_of("xl/_rels/workbook.xml.rels"), "xl/workbook.xml");
        assert_eq!(owner_of("_rels/.rels"), "");
        assert_eq!(resolve("xl/workbook.xml", "worksheets/../worksheets/./sheet1.xml"), "xl/worksheets/sheet1.xml");
        assert_eq!(resolve("xl/worksheets/sheet1.xml", "/xl/media/a.png"), "xl/media/a.png");
    }
}
