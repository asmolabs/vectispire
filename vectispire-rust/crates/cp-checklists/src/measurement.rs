//! What a rule found on a project at one instant — `Measurement` — and the vocabulary it is said in: its outcome,
//! why there is no data when there is none, and an answer beside it (`Reconciliation`).
//!
//! **The evidence is kept as written.** [`Measurement::evidence_json`] is what the measurement's row stores and what
//! its digest covers: the sign-off freezes it with the revision, and an auditor reads next year the evidence that
//! was judged, not a recomputation. Its bytes are Java's, member by member.

use serde_json::Value;
use vectispire_domain::checklists::jackson;
use vectispire_domain::checklists::{Look, Source};
use vectispire_domain::instant::Instant;
use vectispire_domain::wire::write_string;

use crate::answer::ChecklistAnswer;
use crate::{Defect, sha256_hex};

/// What a measurement says of its line. `NoData` is never `Pass`: it is "did not look", with its reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeasurementOutcome {
    Pass,
    Fail,
    NoData,
}

impl MeasurementOutcome {
    pub const ALL: [MeasurementOutcome; 3] =
        [MeasurementOutcome::Pass, MeasurementOutcome::Fail, MeasurementOutcome::NoData];

    pub fn wire_name(self) -> &'static str {
        match self {
            MeasurementOutcome::Pass => "pass",
            MeasurementOutcome::Fail => "fail",
            MeasurementOutcome::NoData => "no_data",
        }
    }

    /// A stored outcome read back; one this version does not know is none of these.
    pub fn of_stored(value: &str) -> Option<MeasurementOutcome> {
        MeasurementOutcome::ALL.into_iter().find(|outcome| outcome.wire_name() == value)
    }
}

/// Why a measurement has no data — a closed set, **declared in the order a headline picks**: when repositories lack
/// data for different reasons, the measurement names the first of them here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NoDataReason {
    NoRepository,
    NeverExamined,
    ForgeUnlinked,
    ForgeUnreadable,
    StepAbsent,
    PluginUnsigned,
    PluginSignatureUnverified,
    /// Thirty-nine characters: the measurement's `reason` column holds forty.
    PluginRegistryAuthenticationRequired,
    LanguageNotAnalysed,
    ExaminationUnrecorded,
    LanguagesUnrecorded,
    InventoryAbsent,
    VersionUnrecorded,
    PackagesUnrecorded,
    PackagesNotKept,
    ScopeMatchesNothing,
    ReviewIncomplete,
    NoChangeMerged,
    Stale,
    NotApplicableAnywhere,
    SuiteNotFound,
    NoTestRan,
}

impl NoDataReason {
    pub const ALL: [NoDataReason; 22] = [
        NoDataReason::NoRepository,
        NoDataReason::NeverExamined,
        NoDataReason::ForgeUnlinked,
        NoDataReason::ForgeUnreadable,
        NoDataReason::StepAbsent,
        NoDataReason::PluginUnsigned,
        NoDataReason::PluginSignatureUnverified,
        NoDataReason::PluginRegistryAuthenticationRequired,
        NoDataReason::LanguageNotAnalysed,
        NoDataReason::ExaminationUnrecorded,
        NoDataReason::LanguagesUnrecorded,
        NoDataReason::InventoryAbsent,
        NoDataReason::VersionUnrecorded,
        NoDataReason::PackagesUnrecorded,
        NoDataReason::PackagesNotKept,
        NoDataReason::ScopeMatchesNothing,
        NoDataReason::ReviewIncomplete,
        NoDataReason::NoChangeMerged,
        NoDataReason::Stale,
        NoDataReason::NotApplicableAnywhere,
        NoDataReason::SuiteNotFound,
        NoDataReason::NoTestRan,
    ];

    pub fn wire_name(self) -> &'static str {
        match self {
            NoDataReason::NoRepository => "no_repository",
            NoDataReason::NeverExamined => "never_examined",
            NoDataReason::ForgeUnlinked => "forge_unlinked",
            NoDataReason::ForgeUnreadable => "forge_unreadable",
            NoDataReason::StepAbsent => "step_absent",
            NoDataReason::PluginUnsigned => "plugin_unsigned",
            NoDataReason::PluginSignatureUnverified => "plugin_signature_unverified",
            NoDataReason::PluginRegistryAuthenticationRequired => "plugin_registry_authentication_required",
            NoDataReason::LanguageNotAnalysed => "language_not_analysed",
            NoDataReason::ExaminationUnrecorded => "examination_unrecorded",
            NoDataReason::LanguagesUnrecorded => "languages_unrecorded",
            NoDataReason::InventoryAbsent => "inventory_absent",
            NoDataReason::VersionUnrecorded => "version_unrecorded",
            NoDataReason::PackagesUnrecorded => "packages_unrecorded",
            NoDataReason::PackagesNotKept => "packages_not_kept",
            NoDataReason::ScopeMatchesNothing => "scope_matches_nothing",
            NoDataReason::ReviewIncomplete => "review_incomplete",
            NoDataReason::NoChangeMerged => "no_change_merged",
            NoDataReason::Stale => "stale",
            NoDataReason::NotApplicableAnywhere => "not_applicable_anywhere",
            NoDataReason::SuiteNotFound => "suite_not_found",
            NoDataReason::NoTestRan => "no_test_ran",
        }
    }

    pub fn of_stored(value: &str) -> Option<NoDataReason> {
        NoDataReason::ALL.into_iter().find(|reason| reason.wire_name() == value)
    }
}

/// An answer beside its line's measurement, in the statement of applicability's vocabulary: the disagreement between
/// what is declared and what is measured is what an assessor opens with, so it is named rather than resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reconciliation {
    /// `yes` and `pass`, or `no` and `fail`.
    Consistent,
    /// `yes` against `fail`: refused at submission.
    Contradicted,
    /// An answer where the measurement has no data.
    DeclaredNotMeasured,
    /// `no` against `pass`: allowed, the comment says why.
    Understated,
    /// `not_applicable`: argued out of scope, whatever the rule measured.
    Excluded,
    /// No rule is bound.
    NotMeasuredHere,
    /// A rule is bound and nobody has answered yet.
    Unanswered,
}

impl Reconciliation {
    pub const ALL: [Reconciliation; 7] = [
        Reconciliation::Consistent,
        Reconciliation::Contradicted,
        Reconciliation::DeclaredNotMeasured,
        Reconciliation::Understated,
        Reconciliation::Excluded,
        Reconciliation::NotMeasuredHere,
        Reconciliation::Unanswered,
    ];

    pub fn wire_name(self) -> &'static str {
        match self {
            Reconciliation::Consistent => "consistent",
            Reconciliation::Contradicted => "contradicted",
            Reconciliation::DeclaredNotMeasured => "declared_not_measured",
            Reconciliation::Understated => "understated",
            Reconciliation::Excluded => "excluded",
            Reconciliation::NotMeasuredHere => "not_measured_here",
            Reconciliation::Unanswered => "unanswered",
        }
    }

    /// The line's reconciliation; no measurement means no rule is bound.
    pub fn of(answer: Option<ChecklistAnswer>, measured: Option<MeasurementOutcome>) -> Reconciliation {
        let Some(measured) = measured else { return Reconciliation::NotMeasuredHere };
        let Some(answer) = answer else { return Reconciliation::Unanswered };
        match (answer, measured) {
            (ChecklistAnswer::NotApplicable, _) => Reconciliation::Excluded,
            (ChecklistAnswer::Yes, MeasurementOutcome::Pass) | (ChecklistAnswer::No, MeasurementOutcome::Fail) => {
                Reconciliation::Consistent
            }
            (ChecklistAnswer::Yes, MeasurementOutcome::Fail) => Reconciliation::Contradicted,
            (ChecklistAnswer::No, MeasurementOutcome::Pass) => Reconciliation::Understated,
            (_, MeasurementOutcome::NoData) => Reconciliation::DeclaredNotMeasured,
        }
    }
}

/// What one repository contributed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryEvidence {
    pub repository_id: i64,
    /// The scope's key for a findings rule; `None` for a kind that reads one thing.
    pub scope: Option<String>,
    /// [`EXAMINED`], [`NOT_APPLICABLE`], or the [`NoDataReason`] it lacks data for.
    pub status: String,
    /// The scan or import read — for a repository without data, the newest there was, if any.
    pub look: Option<Look>,
    /// Whether this repository meets the rule's per-repository conditions.
    pub met: Option<bool>,
    pub detail: Option<String>,
}

pub const EXAMINED: &str = "examined";
pub const NOT_APPLICABLE: &str = "not_applicable";

/// A figure over the project: issues of one severity in one scope, open and resolved — or, under the scope
/// [`ALL_SCOPES`], the total a threshold was judged on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Figure {
    pub scope: String,
    pub severity: String,
    pub open: i64,
    pub resolved: i64,
    pub met: Option<bool>,
    pub detail: Option<String>,
}

pub const ALL_SCOPES: &str = "all";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Measurement {
    pub outcome: MeasurementOutcome,
    pub reason: Option<NoDataReason>,
    /// The oldest evidence it rests on.
    pub as_of: Option<Instant>,
    pub repositories: Vec<RepositoryEvidence>,
    pub figures: Vec<Figure>,
    /// One sentence in English, for the audit entry and a document's evidence column.
    pub summary: String,
}

impl Measurement {
    pub fn new(
        outcome: MeasurementOutcome,
        reason: Option<NoDataReason>,
        as_of: Option<Instant>,
        repositories: Vec<RepositoryEvidence>,
        figures: Vec<Figure>,
        summary: String,
    ) -> Result<Measurement, Defect> {
        if (outcome == MeasurementOutcome::NoData) != reason.is_some() {
            return Err(Defect("A reason is given for no data, and only for no data.".to_owned()));
        }
        Ok(Measurement { outcome, reason, as_of, repositories, figures, summary })
    }

    /// The evidence as stored, keys in a fixed order: outcome, reason, as of, repositories, figures, summary.
    pub fn evidence_json(&self) -> String {
        let mut out = String::from("{\"outcome\":");
        write_string(&mut out, self.outcome.wire_name());
        out.push_str(",\"reason\":");
        optional(&mut out, self.reason.map(NoDataReason::wire_name));
        out.push_str(",\"asOf\":");
        optional(&mut out, self.as_of.and_then(Instant::to_java_string).as_deref());
        out.push_str(",\"repositories\":[");
        for (index, repository) in self.repositories.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str(&format!("{{\"repositoryId\":{},\"scope\":", repository.repository_id));
            optional(&mut out, repository.scope.as_deref());
            out.push_str(",\"status\":");
            write_string(&mut out, &repository.status);
            match &repository.look {
                Some(look) => {
                    out.push_str(",\"source\":");
                    write_string(&mut out, look.source.wire_name());
                    out.push_str(&format!(",\"sourceId\":{},\"at\":", look.id));
                    write_string(&mut out, &look.at.to_java_string().unwrap_or_default());
                    out.push_str(",\"digest\":");
                    optional(&mut out, look.digest.as_deref());
                }
                None => out.push_str(",\"source\":null,\"sourceId\":null,\"at\":null,\"digest\":null"),
            }
            out.push_str(",\"met\":");
            out.push_str(repository.met.map_or("null", |met| if met { "true" } else { "false" }));
            out.push_str(",\"detail\":");
            optional(&mut out, repository.detail.as_deref());
            out.push('}');
        }
        out.push_str("],\"figures\":[");
        for (index, figure) in self.figures.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            out.push_str("{\"scope\":");
            write_string(&mut out, &figure.scope);
            out.push_str(",\"severity\":");
            write_string(&mut out, &figure.severity);
            out.push_str(&format!(",\"open\":{},\"resolved\":{},\"met\":", figure.open, figure.resolved));
            out.push_str(figure.met.map_or("null", |met| if met { "true" } else { "false" }));
            out.push_str(",\"detail\":");
            optional(&mut out, figure.detail.as_deref());
            out.push('}');
        }
        out.push_str("],\"summary\":");
        write_string(&mut out, &self.summary);
        out.push('}');
        out
    }

    /// SHA-256 of [`evidence_json`](Measurement::evidence_json): two measurements with the same digest judged the
    /// same evidence.
    pub fn evidence_digest(&self) -> String {
        sha256_hex(&self.evidence_json())
    }

    /// A stored measurement's evidence read back, as `evidence_json` wrote it; one that does not read is a defect.
    pub fn read(evidence_json: &str) -> Result<Measurement, Defect> {
        let node = jackson::read_tree(evidence_json)
            .map_err(|_| Defect("A stored measurement does not read as JSON.".to_owned()))?
            .unwrap_or(Value::Null);
        let outcome = MeasurementOutcome::of_stored(&jackson::as_text(jackson::get(&node, "outcome")))
            .ok_or_else(|| Defect("A stored measurement has no outcome this version knows.".to_owned()))?;
        let mut repositories = Vec::new();
        for entry in elements(jackson::get(&node, "repositories")) {
            let look = match jackson::text(entry, "source") {
                None => None,
                Some(source) => {
                    let source = Source::from_wire_name(&source)
                        .ok_or_else(|| Defect(format!("Unknown evidence source {source}")))?;
                    let at = jackson::as_text(jackson::get(entry, "at"));
                    Some(Look {
                        source,
                        id: jackson::as_long(jackson::get(entry, "sourceId")),
                        at: Instant::parse_java(&at)
                            .ok_or_else(|| Defect(format!("Text '{at}' could not be parsed")))?,
                        digest: jackson::text(entry, "digest"),
                    })
                }
            };
            repositories.push(RepositoryEvidence {
                repository_id: jackson::as_long(jackson::get(entry, "repositoryId")),
                scope: jackson::text(entry, "scope"),
                status: jackson::as_text(jackson::get(entry, "status")),
                look,
                met: boolean(entry, "met"),
                detail: jackson::text(entry, "detail"),
            });
        }
        let figures = elements(jackson::get(&node, "figures"))
            .map(|entry| Figure {
                scope: jackson::as_text(jackson::get(entry, "scope")),
                severity: jackson::as_text(jackson::get(entry, "severity")),
                open: jackson::as_long(jackson::get(entry, "open")),
                resolved: jackson::as_long(jackson::get(entry, "resolved")),
                met: boolean(entry, "met"),
                detail: jackson::text(entry, "detail"),
            })
            .collect();
        let as_of = match jackson::text(&node, "asOf") {
            None => None,
            Some(at) => {
                Some(Instant::parse_java(&at).ok_or_else(|| Defect(format!("Text '{at}' could not be parsed")))?)
            }
        };
        let summary = match jackson::get(&node, "summary") {
            None | Some(Value::Null) => String::new(),
            Some(value) => jackson::as_text(Some(value)),
        };
        Measurement::new(
            outcome,
            jackson::text(&node, "reason").and_then(|reason| NoDataReason::of_stored(&reason)),
            as_of,
            repositories,
            figures,
            summary,
        )
    }
}

/// What a Jackson loop over `path(name)` visits: an array's elements, an object's values, nothing else.
fn elements(node: Option<&Value>) -> Box<dyn Iterator<Item = &Value> + '_> {
    match node {
        Some(Value::Array(items)) => Box::new(items.iter()),
        Some(Value::Object(members)) => Box::new(members.values()),
        _ => Box::new(std::iter::empty()),
    }
}

fn boolean(node: &Value, name: &str) -> Option<bool> {
    match jackson::get(node, name) {
        None | Some(Value::Null) => None,
        value => Some(jackson::as_boolean(value)),
    }
}

fn optional(out: &mut String, value: Option<&str>) {
    match value {
        None => out.push_str("null"),
        Some(text) => write_string(out, text),
    }
}
