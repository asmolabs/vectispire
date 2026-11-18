//! An imported checklist template (`.xlsx`): whatever the archive holds — a cut or forged header, a bomb, a part
//! that is not well-formed XML, a sheet of any shape — reading it must answer, never panic, and a workbook it
//! reads is then proposed a layout and, when one is found, rendered as a publication's trial renders it: the
//! renderer splices the very parts the reader accepted.
#![no_main]

use libfuzzer_sys::fuzz_target;
use vectispire_cp_checklists::answer::AnswerWords;
use vectispire_cp_checklists::layout::{LayoutProposal, TemplateVersion};
use vectispire_cp_checklists::renderer;
use vectispire_cp_checklists::workbook::{Limits, Workbook};
use vectispire_cp_checklists::workbook_reader;

/// Small enough that one input stays within the fuzzer's time budget; the guards are the same code at any size.
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

fuzz_target!(|data: &[u8]| {
    let size = i64::try_from(data.len()).unwrap_or(i64::MAX);
    let _ = workbook_reader::entries(data, size, LIMITS);
    let Ok(workbook) = Workbook::read_with(data, size, LIMITS) else { return };
    let Ok(proposal) = LayoutProposal::of(&workbook) else { return };
    let Ok(words) = AnswerWords::new(Some("Yes"), Some("No"), None) else { return };
    let Ok(layout) = proposal.confirm(words) else { return };
    let Ok(version) = TemplateVersion::read(&workbook, layout.clone()) else { return };
    let _ = renderer::trial(data, &layout, &version.items);
});
