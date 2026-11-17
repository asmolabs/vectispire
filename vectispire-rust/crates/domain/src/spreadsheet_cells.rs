//! Formula neutralisation, for every CSV handed to a spreadsheet — Java's `SpreadsheetCells`.
//!
//! **One place**, because two copies had become one and a half: a later export doubled its quotes and nothing else,
//! and served repository names and triage comments to auditors as live formulas. Quoting does not protect — the
//! spreadsheet strips the quotes before evaluating — so neutralisation comes first.

/// The value, forced to text when a spreadsheet would evaluate it — `neutralize`. Excel, LibreOffice and Google Sheets
/// evaluate a cell starting with `=`, `+`, `-` or `@`; Excel skips a leading tab or carriage return before resuming
/// its parse, so `\t=cmd|…` is a formula too. A leading apostrophe forces text mode.
pub fn neutralize(value: &str) -> String {
    if value.starts_with(['=', '+', '-', '@', '\t', '\r']) { format!("'{value}") } else { value.to_owned() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_formula_is_text_and_a_newline_is_not_a_prefix() {
        assert_eq!(neutralize("=cmd|' /c calc'!A1"), "'=cmd|' /c calc'!A1");
        assert_eq!(neutralize("\t=1"), "'\t=1");
        assert_eq!(neutralize("\n=1"), "\n=1");
        assert_eq!(neutralize(""), "");
    }
}
