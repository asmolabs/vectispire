//! What a setting's value has to look like (`SettingType`), where the screen files it (`Setting.Section`), and how
//! much protection it needs (`Setting.Sensitivity`).
//!
//! **Validated at the point of entry, never on read**: an unreadable integer read later falls back to its default,
//! and the operator never learns their value was ignored.

/// `BoundedText.TEXT_MAX`: the ceiling every stored text shares — the column is `text` since V38, and past it the
/// database would refuse the write as a 500.
pub const TEXT_MAX: usize = 16_000;

/// The severities a threshold may name, in order — deliberately narrower than every severity: a threshold of
/// "unknown" notifies on everything, and offering it is offering a way to flood the channel by accident.
pub const THRESHOLDS: [&str; 4] = ["critical", "high", "medium", "low"];

/// A setting's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SettingType {
    Boolean,
    Integer,
    Severity,
    Text,
}

const INTEGER_MESSAGE: &str = "Expected value: a positive integer or zero.";

impl SettingType {
    /// The Java constant's name.
    pub const fn name(self) -> &'static str {
        match self {
            SettingType::Boolean => "BOOLEAN",
            SettingType::Integer => "INTEGER",
            SettingType::Severity => "SEVERITY",
            SettingType::Text => "TEXT",
        }
    }

    /// `None` when the value is acceptable, otherwise the message to show — Java's, word for word.
    pub fn validate(self, value: Option<&str>) -> Option<String> {
        match self {
            SettingType::Boolean => {
                (!matches!(value, Some("true" | "false"))).then(|| "Expected value: \"true\" or \"false\".".to_owned())
            }
            SettingType::Integer => match value {
                Some(value) if !is_blank(value) && parse_int(value).is_some_and(|number| number >= 0) => None,
                _ => Some(INTEGER_MESSAGE.to_owned()),
            },
            SettingType::Severity => (!value.is_some_and(|value| THRESHOLDS.contains(&value)))
                .then(|| "Expected value: critical, high, medium or low.".to_owned()),
            // Free text: what it has to *mean* is checked by whoever reads it. How long it may be is the column's
            // rule, and checked here.
            SettingType::Text => too_long(value, TEXT_MAX, "The value"),
        }
    }
}

/// `BoundedText.tooLong`: past `max` UTF-16 code units, as `String.length` counts them.
pub fn too_long(value: Option<&str>, max: usize, what: &str) -> Option<String> {
    value.filter(|value| value.encode_utf16().count() > max).map(|_| format!("{what} is longer than {max} characters."))
}

/// `Integer.parseInt(value.trim())`: an optional sign, then one or more decimal digits of any script
/// `Character.digit` knows, within `i32`. `None` where Java throws.
pub fn parse_int(value: &str) -> Option<i32> {
    let trimmed = value.trim_matches(|c: char| c <= ' ');
    let (negative, digits) = match trimmed.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, trimmed.strip_prefix('+').unwrap_or(trimmed)),
    };
    if digits.is_empty() {
        return None;
    }
    // Past 2³¹ nothing more can fit, whatever the sign: stop there rather than read a million digits.
    const BEYOND: i64 = 2_147_483_648;
    let mut total: i64 = 0;
    for c in digits.chars() {
        total = total.checked_mul(10)?.checked_add(i64::from(decimal_digit(c)?))?;
        if total > BEYOND {
            return None;
        }
    }
    let signed = if negative { total.checked_neg()? } else { total };
    i32::try_from(signed).ok()
}

/// The code points `Character.digit(c, 10)` reads as zero; each starts a run of ten digits. Written by the Java
/// side (`reference/settings/digit-zeros.txt`), and held to it by the reference test.
pub const DIGIT_ZEROS: [u32; 76] = [
    0x30, 0x660, 0x6F0, 0x7C0, 0x966, 0x9E6, 0xA66, 0xAE6, 0xB66, 0xBE6, 0xC66, 0xCE6, 0xD66, 0xDE6, 0xE50, 0xED0,
    0xF20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80, 0x1A90, 0x1B50, 0x1BB0, 0x1C40, 0x1C50, 0xA620,
    0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0, 0xFF10, 0x104A0, 0x10D30, 0x10D40, 0x11066, 0x110F0, 0x11136,
    0x111D0, 0x112F0, 0x11450, 0x114D0, 0x11650, 0x116C0, 0x116D0, 0x116DA, 0x11730, 0x118E0, 0x11950, 0x11BF0,
    0x11C50, 0x11D50, 0x11DA0, 0x11F50, 0x16130, 0x16A60, 0x16AC0, 0x16B50, 0x16D70, 0x1CCF0, 0x1D7CE, 0x1D7D8,
    0x1D7E2, 0x1D7EC, 0x1D7F6, 0x1E140, 0x1E2F0, 0x1E4F0, 0x1E5F1, 0x1E950, 0x1FBF0,
];

/// `Character.digit(c, 10)`, `None` for -1.
pub fn decimal_digit(c: char) -> Option<u32> {
    let code = u32::from(c);
    DIGIT_ZEROS.iter().find_map(|zero| code.checked_sub(*zero).filter(|offset| *offset < 10))
}

/// `String.isBlank`: only white space as `Character.isWhitespace` reads it.
pub fn is_blank(value: &str) -> bool {
    value.chars().all(|c| {
        let space_separator = matches!(
            c,
            '\u{20}' | '\u{a0}' | '\u{1680}' | '\u{2000}'
                ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}'
        );
        matches!(c, '\u{9}'..='\u{d}' | '\u{1c}'..='\u{1f}')
            || (space_separator && !matches!(c, '\u{a0}' | '\u{2007}' | '\u{202f}'))
    })
}

/// The group the screen files a setting under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Section {
    Access,
    Triage,
    Enrichment,
    EndOfLife,
    SourceCode,
    Scheduling,
    Remediation,
    Retention,
    Notifications,
    Licenses,
    Checklists,
    Tickets,
    ModelReview,
}

impl Section {
    /// The Java constant's name.
    pub const fn name(self) -> &'static str {
        match self {
            Section::Access => "ACCESS",
            Section::Triage => "TRIAGE",
            Section::Enrichment => "ENRICHMENT",
            Section::EndOfLife => "END_OF_LIFE",
            Section::SourceCode => "SOURCE_CODE",
            Section::Scheduling => "SCHEDULING",
            Section::Remediation => "REMEDIATION",
            Section::Retention => "RETENTION",
            Section::Notifications => "NOTIFICATIONS",
            Section::Licenses => "LICENSES",
            Section::Checklists => "CHECKLISTS",
            Section::Tickets => "TICKETS",
            Section::ModelReview => "MODEL_REVIEW",
        }
    }

    /// The heading the screen shows.
    pub const fn label(self) -> &'static str {
        match self {
            Section::Access => "Access",
            Section::Triage => "VEX Triage & Approval",
            Section::Enrichment => "Enrichment",
            Section::EndOfLife => "End of life",
            Section::SourceCode => "Source code analysis",
            Section::Scheduling => "Scheduling",
            Section::Remediation => "Remediation deadlines",
            Section::Retention => "Retention",
            Section::Notifications => "Notifications",
            Section::Licenses => "Licenses",
            Section::Checklists => "Security checklists",
            Section::Tickets => "Ticket tracker",
            Section::ModelReview => "OWASP review",
        }
    }
}

/// How much protection a value needs — **two questions and not one**: whether a non-administrator may read it,
/// and whether it is a credential written only by its own route and never returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sensitivity {
    /// Ordinary configuration, readable by any signed-in account.
    Plain,
    /// Stored as written, hidden from non-administrators: a capability rather than a credential.
    Secret,
    /// A credential: encrypted at rest, written only by its own route, never returned.
    Encrypted,
}

impl Sensitivity {
    /// The Java constant's name.
    pub const fn name(self) -> &'static str {
        match self {
            Sensitivity::Plain => "PLAIN",
            Sensitivity::Secret => "SECRET",
            Sensitivity::Encrypted => "ENCRYPTED",
        }
    }
}
