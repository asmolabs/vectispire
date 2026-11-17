//! The OWASP grid as served — Java's `OwaspGridService` and `OwaspGridCsv`: each category's line with the
//! organisation's declaration beside it, and the same as a spreadsheet.

use std::collections::HashMap;

use serde::Serialize;
use vectispire_cp_access::Allowance;
use vectispire_domain::owasp_coverage::{CoverageLine, CoverageReason, State};
use vectispire_domain::spreadsheet_cells;

use crate::coverage::{OwaspCoverageService, ScopedGrid, StatedScope};
use crate::decisions::Declaration;
use crate::declarations::StatementOfApplicabilityService;
use crate::error::ComplianceError;
use crate::owasp_words::{self, AdviceLanguage};

/// The key the OWASP Top 10 is declared under: not a compliance framework, declared beside them.
pub const FRAMEWORK: &str = "OWASP_2021";

/// `DeclaredCoverageLine`, members in the record's order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeclaredCoverageLine {
    pub id: &'static str,
    pub title: &'static str,
    pub state: State,
    pub findings: i64,
    pub because: String,
    pub reason: CoverageReason,
    pub declaration: Option<Declaration>,
}

/// `DeclaredGrid`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeclaredGrid {
    pub lines: Vec<DeclaredCoverageLine>,
    pub covered: i32,
    pub with_findings: i32,
    pub unmeasured: i32,
    pub scope: Option<StatedScope>,
    pub unplaced_code: i64,
}

#[derive(Debug, Clone)]
pub struct OwaspGridService {
    coverage: OwaspCoverageService,
    declarations: StatementOfApplicabilityService,
}

impl OwaspGridService {
    pub fn new(coverage: OwaspCoverageService, declarations: StatementOfApplicabilityService) -> OwaspGridService {
        OwaspGridService { coverage, declarations }
    }

    /// The grid over the scope named, or the caller's estate. **The declarations are per category and do not depend
    /// on the scope.**
    pub async fn grid(
        &self,
        project_id: Option<i64>,
        solution_id: Option<i64>,
        allowance: &Allowance,
    ) -> Result<DeclaredGrid, ComplianceError> {
        let scoped = self.coverage.scoped(project_id, solution_id, allowance).await?;
        let by_category = self.by_category().await?;
        Ok(declared(scoped, &by_category))
    }

    /// `csv`: the language read **before** the scope, as Java reads it — a bad language is refused before a hidden
    /// project.
    pub async fn csv(
        &self,
        project_id: Option<i64>,
        solution_id: Option<i64>,
        allowance: &Allowance,
        language: Option<&str>,
    ) -> Result<String, ComplianceError> {
        let words = AdviceLanguage::parse(language)?;
        let scoped = self.coverage.scoped(project_id, solution_id, allowance).await?;
        let by_category = self.by_category().await?;
        Ok(render(&scoped.grid.lines, &by_category, scoped.scope.as_ref(), words))
    }

    async fn by_category(&self) -> Result<HashMap<String, Declaration>, ComplianceError> {
        Ok(self
            .declarations
            .declarations(FRAMEWORK)
            .await?
            .into_iter()
            .map(|declaration| (declaration.control_id.clone(), declaration))
            .collect())
    }
}

fn declared(scoped: ScopedGrid, by_category: &HashMap<String, Declaration>) -> DeclaredGrid {
    let grid = scoped.grid;
    DeclaredGrid {
        lines: grid
            .lines
            .into_iter()
            .map(|line| DeclaredCoverageLine {
                declaration: by_category.get(line.id).cloned(),
                id: line.id,
                title: line.title,
                state: line.state,
                findings: line.findings,
                because: line.because,
                reason: line.reason,
            })
            .collect(),
        covered: grid.covered,
        with_findings: grid.with_findings,
        unmeasured: grid.unmeasured,
        scope: scoped.scope,
        unplaced_code: scoped.unplaced_code,
    }
}

const HEADER: [&str; 19] = [
    "category",
    "title",
    "state",
    "findings",
    "reason_code",
    "reason",
    "declaration_applicability",
    "declaration_justification",
    "declaration_implementation",
    "declaration_evidence_source",
    "declaration_external_evidence",
    "declaration_owner",
    "declaration_decided_by",
    "declaration_decided_at",
    "declaration_review_due_at",
    "scope_kind",
    "scope_id",
    "scope_name",
    "scope_partial",
];

/// `OwaspGridCsv.render`: the header bare, then one row per category, **every row CRLF-terminated** — the last
/// included — every cell neutralized against formulas, then quoted; an absent value an empty quoted cell.
pub fn render(
    lines: &[CoverageLine],
    declarations: &HashMap<String, Declaration>,
    scope: Option<&StatedScope>,
    language: AdviceLanguage,
) -> String {
    let mut csv = HEADER.join(",");
    csv.push_str("\r\n");
    for line in lines {
        let declaration = declarations.get(line.id);
        let of = |read: &dyn Fn(&Declaration) -> Option<String>| declaration.and_then(read);
        let cells: [Option<String>; 19] = [
            Some(line.id.to_owned()),
            Some(line.title.to_owned()),
            wire(line.state),
            Some(line.findings.to_string()),
            wire(line.reason.code),
            Some(owasp_words::reason(line, language)),
            of(&|d| d.applicability.and_then(wire)),
            of(&|d| d.justification.clone()),
            of(&|d| d.implementation.and_then(wire)),
            of(&|d| d.evidence_source.and_then(wire)),
            of(&|d| d.external_evidence.clone()),
            of(&|d| d.owner.clone()),
            of(&|d| d.decided_by.clone()),
            of(&|d| d.decided_at.and_then(|at| at.to_java_string())),
            of(&|d| d.review_due_at.and_then(|at| at.to_java_string())),
            Some(scope.map_or("estate", |scope| scope.kind).to_owned()),
            scope.map(|scope| scope.id.to_string()),
            scope.map(|scope| scope.name.clone()),
            scope.map(|scope| scope.partial.to_string()),
        ];
        let row: Vec<String> = cells.iter().map(|cell| quote(cell.as_deref())).collect();
        csv.push_str(&row.join(","));
        csv.push_str("\r\n");
    }
    csv
}

fn quote(value: Option<&str>) -> String {
    let safe = value.map(spreadsheet_cells::neutralize).unwrap_or_default();
    format!("\"{}\"", safe.replace('"', "\"\""))
}

/// An enum's constant name, as Java's `name()` writes it.
fn wire<T: Serialize>(value: T) -> Option<String> {
    match serde_json::to_value(value).ok()? {
        serde_json::Value::String(name) => Some(name),
        _ => None,
    }
}
