//! What a person answers on a line, who wrote it, and the template's own words for each answer.

use vectispire_domain::bounded_text::{self, clip};
use vectispire_domain::java;

use crate::{Refused, refused, text};

/// `ChecklistAnswer`: what an answer *means*, whatever words the template uses for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ChecklistAnswer {
    Yes,
    No,
    /// Offered only by a version whose importer mapped a word to it (decision 0032, question 1).
    NotApplicable,
}

impl ChecklistAnswer {
    pub const ALL: [ChecklistAnswer; 3] = [ChecklistAnswer::Yes, ChecklistAnswer::No, ChecklistAnswer::NotApplicable];

    /// A negative answer without its reason is the line a reader needs most; "not applicable" without one is an
    /// exclusion nobody argued.
    pub fn requires_comment(self) -> bool {
        self != ChecklistAnswer::Yes
    }

    pub fn wire_name(self) -> &'static str {
        match self {
            ChecklistAnswer::Yes => "yes",
            ChecklistAnswer::No => "no",
            ChecklistAnswer::NotApplicable => "not_applicable",
        }
    }

    /// `ChecklistAnswer.parse`: stripped and lowered, one of the three — or a refusal listing them.
    pub fn parse(value: Option<&str>) -> Result<ChecklistAnswer, Refused> {
        let stripped = java::strip(value.unwrap_or(""));
        let normalized = java::to_lower_root(stripped);
        ChecklistAnswer::ALL.into_iter().find(|answer| answer.wire_name() == normalized).ok_or_else(|| {
            refused(format!(
                "An answer is one of yes, no, not_applicable{}.",
                if normalized.is_empty() {
                    String::new()
                } else {
                    format!("; \"{}\" is not one of them", clip(Some(stripped), 40).unwrap_or(""))
                }
            ))
        })
    }
}

/// `AnswerAuthor`: a person, or Vectispire from a measurement — **a kind, never a name**: an account may be called
/// "Vectispire", and telling an automatic answer by its author's name would let anybody so named pass for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnswerAuthor {
    Person,
    System,
}

impl AnswerAuthor {
    pub const ALL: [AnswerAuthor; 2] = [AnswerAuthor::Person, AnswerAuthor::System];

    /// The name a system answer is written under, for a reader who shows names — never how one is recognised.
    pub const SYSTEM_NAME: &'static str = "Vectispire";

    pub fn wire_name(self) -> &'static str {
        match self {
            AnswerAuthor::Person => "person",
            AnswerAuthor::System => "system",
        }
    }

    /// A stored kind; `None` for one this version does not know.
    pub fn of_stored(stored: Option<&str>) -> Option<AnswerAuthor> {
        AnswerAuthor::ALL.into_iter().find(|kind| Some(kind.wire_name()) == stored)
    }

    /// Whether a stored kind is the system's. One this version does not know is a person's: its answer is never
    /// replaced by the scans — the safe way to err.
    pub fn is_system(stored: Option<&str>) -> bool {
        AnswerAuthor::of_stored(stored) == Some(AnswerAuthor::System)
    }
}

/// `AnswerWords`: the template's own words for each answer, **mapped by a person, never recognised** — deciding that
/// "Oui" is yes would build one organisation's vocabulary into the product. Kept as mapped, trimmed, never re-cased:
/// the renderer writes them back into the workbook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnswerWords {
    yes: String,
    no: String,
    not_applicable: Option<String>,
}

impl AnswerWords {
    pub const MAX_WORD: usize = 255;

    pub fn new(yes: Option<&str>, no: Option<&str>, not_applicable: Option<&str>) -> Result<AnswerWords, Refused> {
        let yes = bounded_text::required(yes, AnswerWords::MAX_WORD, "The word for yes")?;
        let no = bounded_text::required(no, AnswerWords::MAX_WORD, "The word for no")?;
        let not_applicable = not_applicable
            .map(|word| bounded_text::required(Some(word), AnswerWords::MAX_WORD, "The word for not applicable"))
            .transpose()?;
        if same(&yes, &no) {
            return Err(refused(format!(
                "Yes and no are mapped to the same word, \"{yes}\": an answer written in the workbook could not be read \
                 back."
            )));
        }
        if let Some(word) = not_applicable.as_deref().filter(|word| same(word, &yes) || same(word, &no)) {
            return Err(refused(format!(
                "Not applicable is mapped to \"{word}\", a word already mapped to yes or no."
            )));
        }
        Ok(AnswerWords { yes, no, not_applicable })
    }

    pub fn yes(&self) -> &str {
        &self.yes
    }

    pub fn no(&self) -> &str {
        &self.no
    }

    pub fn not_applicable(&self) -> Option<&str> {
        self.not_applicable.as_deref()
    }

    pub fn offers_not_applicable(&self) -> bool {
        self.not_applicable.is_some()
    }

    /// The word the renderer writes for an answer; "not applicable" refused on a version that does not offer it.
    pub fn word(&self, answer: ChecklistAnswer) -> Result<&str, Refused> {
        match answer {
            ChecklistAnswer::Yes => Ok(&self.yes),
            ChecklistAnswer::No => Ok(&self.no),
            ChecklistAnswer::NotApplicable => self
                .not_applicable
                .as_deref()
                .ok_or_else(|| refused("This version of the template does not offer \"not applicable\".")),
        }
    }

    /// The word a document writes: [`word`](AnswerWords::word), and "Not applicable" in words for one this version
    /// does not offer — only a draft holds one, a carried line awaiting confirmation, and a draft still renders.
    pub fn written(&self, answer: ChecklistAnswer) -> &str {
        self.word(answer).unwrap_or("Not applicable")
    }

    /// The answer a cell's word stands for, compared as the words are distinguished; `None` when it is none of them.
    pub fn answer_of(&self, word: Option<&str>) -> Option<ChecklistAnswer> {
        let word = word?;
        if same(word, &self.yes) {
            return Some(ChecklistAnswer::Yes);
        }
        if same(word, &self.no) {
            return Some(ChecklistAnswer::No);
        }
        self.not_applicable.as_deref().filter(|mapped| same(word, mapped)).map(|_| ChecklistAnswer::NotApplicable)
    }
}

/// Case and spacing aside, as a spreadsheet's list validation compares: two words it would accept for one another
/// cannot be two answers.
fn same(left: &str, right: &str) -> bool {
    java::to_lower_root(&text::normalize(Some(left))) == java::to_lower_root(&text::normalize(Some(right)))
}

/// `GivenAnswer`: an answer to one line as a person gives it, checked against what the version offers before
/// anything is written. The author and the instant are the principal's and the clock's, never the caller's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GivenAnswer {
    pub value: ChecklistAnswer,
    pub comment: Option<String>,
}

impl GivenAnswer {
    /// Bounded before the write; longer is a document, attached as evidence.
    pub const MAX_COMMENT: usize = 4_000;

    pub fn new(value: ChecklistAnswer, comment: Option<&str>) -> Result<GivenAnswer, Refused> {
        let comment = bounded_text::optional(comment, GivenAnswer::MAX_COMMENT, "The comment")?;
        if value.requires_comment() && comment.is_none() {
            return Err(refused(if value == ChecklistAnswer::No {
                "A \"no\" needs a comment saying why: it is the line the reader of the checklist needs most."
            } else {
                "\"Not applicable\" needs a comment saying why the line does not apply."
            }));
        }
        Ok(GivenAnswer { value, comment })
    }

    /// `GivenAnswer.of`: "not applicable" refused first on a version that does not offer it.
    pub fn of(value: ChecklistAnswer, comment: Option<&str>, offered: &AnswerWords) -> Result<GivenAnswer, Refused> {
        if value == ChecklistAnswer::NotApplicable && !offered.offers_not_applicable() {
            return Err(refused("This version of the template does not offer \"not applicable\"."));
        }
        GivenAnswer::new(value, comment)
    }
}
