//! The reader and the renderer never panic on a corrupted workbook — the night's fuzzer (`checklist_workbook`) in a
//! few thousand fixed cases, so that a panic is found by the gate and not a night later.
//!
//! Two layers: the archive's bytes, flipped, cut, repeated, over every workbook of the reference set (most land in
//! the zip's guards); and the parts' own text, mutated where XML decides something (`<`, `&`, quotes, a colon, a
//! cut) and zipped again with correct sizes and CRCs, so that the mutation reaches the XML reader, the proposal and
//! the renderer's splices rather than stopping at a checksum.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use vectispire_cp_checklists::answer::AnswerWords;
use vectispire_cp_checklists::document_zip::{self, Entry};
use vectispire_cp_checklists::layout::{LayoutProposal, TemplateVersion};
use vectispire_cp_checklists::renderer;
use vectispire_cp_checklists::workbook::{Limits, Workbook};
use vectispire_cp_checklists::workbook_reader;

const LIMITS: Limits = Limits {
    max_entries: 64,
    max_entry_bytes: 1 << 20,
    max_inflated_bytes: 4 << 20,
    max_ratio: 100,
    ratio_grace_bytes: 100 * 1024,
    max_elements: 100_000,
    max_sheets: 16,
    max_cells: 50_000,
    max_shared_strings: 50_000,
};

/// What the fuzz target does with one input; any outcome but a panic is an answer.
fn pipeline(data: &[u8]) -> bool {
    let size = i64::try_from(data.len()).unwrap();
    let _ = workbook_reader::entries(data, size, LIMITS);
    let Ok(workbook) = Workbook::read_with(data, size, LIMITS) else { return false };
    let Ok(proposal) = LayoutProposal::of(&workbook) else { return true };
    let Ok(layout) = proposal.confirm(AnswerWords::new(Some("Yes"), Some("No"), None).unwrap()) else { return true };
    let Ok(version) = TemplateVersion::read(&workbook, layout.clone()) else { return true };
    let _ = renderer::trial(data, &layout, &version.items);
    true
}

/// xorshift64*: the same cases on every run and every machine.
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(bound.max(1)).unwrap()).unwrap()
    }
}

fn workbooks() -> Vec<Vec<u8>> {
    let inputs = vectispire_testkit::read_json("checklists/workbooks.json");
    inputs["workbooks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| STANDARD.decode(case["xlsx"].as_str().unwrap()).unwrap())
        .filter(|bytes| bytes.len() < 64 * 1024)
        .collect()
}

#[test]
fn a_corrupted_archive_is_answered_never_panicked_on() {
    let mut random = Random(0x9E37_79B9_7F4A_7C15);
    for original in workbooks() {
        for _ in 0..12 {
            let mut bytes = original.clone();
            match random.below(4) {
                0 => {
                    for _ in 0..=random.below(4) {
                        let at = random.below(bytes.len());
                        if let Some(byte) = bytes.get_mut(at) {
                            *byte ^= 1 << random.below(8);
                        }
                    }
                }
                1 => bytes.truncate(random.below(bytes.len())),
                2 => {
                    let from = random.below(bytes.len());
                    let to = (from + random.below(64)).min(bytes.len());
                    let slice = bytes[from..to].to_vec();
                    let at = random.below(bytes.len());
                    bytes.splice(at..at, slice);
                }
                _ => {
                    let at = random.below(bytes.len());
                    let to = (at + random.below(16)).min(bytes.len());
                    bytes[at..to].fill(0xFF);
                }
            }
            pipeline(&bytes);
        }
    }
}

#[test]
fn a_corrupted_part_is_answered_never_panicked_on() {
    let fixture = &workbooks()[0];
    let entries = workbook_reader::entries(fixture, i64::try_from(fixture.len()).unwrap(), Limits::DEFAULT).unwrap();
    let tokens: [&[u8]; 14] =
        [b"<", b">", b"&", b"\"", b"'", b":", b"/>", b"</", b"<!--", b"]]>", b"&#x0;", b"<?x?>", b"\xff", b"r=\"0\""];
    let mut random = Random(0xD1B5_4A32_D192_ED03);
    let mut reached = 0;
    for round in 0..3_000 {
        let target = random.below(entries.len());
        let mut part = entries[target].bytes.clone();
        for _ in 0..=random.below(3) {
            let at = random.below(part.len() + 1);
            match random.below(3) {
                0 => {
                    let token = tokens[random.below(tokens.len())];
                    part.splice(at..at, token.iter().copied());
                }
                1 => {
                    let to = (at + random.below(24)).min(part.len());
                    part.drain(at..to);
                }
                _ => part.truncate(at),
            }
        }
        let rezipped: Vec<(String, Entry)> = entries
            .iter()
            .enumerate()
            .map(|(index, entry)| {
                let bytes = if index == target { part.clone() } else { entry.bytes.clone() };
                (entry.name.clone(), Entry { bytes, stored: round % 2 == 0, directory: entry.directory })
            })
            .collect();
        if pipeline(&document_zip::of(&rezipped).unwrap()) {
            reached += 1;
        }
    }
    // Most mutations break a part, but enough leave it readable for the proposal and the renderer to be reached.
    assert!(reached > 300, "only {reached} mutated workbooks were read: the renderer was hardly exercised");
}
