//! `ImportMapping`: where an import files each repository — the solution and project the forge's layout suggests,
//! then whatever a person changed. **Proposed, shown, editable — never inferred** (decision 0023).
//!
//! GitLab: the top-level group is the solution, the repository's parent group below it the project; a repository
//! directly under the top-level group goes to a project named after that group. GitHub: the organisation is the
//! solution and each repository its own project. A personal namespace: neither. Rules apply from the shallowest
//! namespace to the deepest, then the repository's own.

use std::collections::HashSet;

use super::{DiscoveredRepository, ForgeKind};
use crate::bounded_text::{self, Refused};
use crate::java;

/// The width of `t_solution.name` and `t_project.name`.
pub const NAME_LENGTH: usize = 100;

/// More than a screen sends for a thousand repositories, each with a rule of its own and its namespace's.
pub const MAX_RULES: usize = 5_000;

/// One change to the proposal, as the request gives it — or, once validated, as kept.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Rule {
    pub namespace_path: Option<String>,
    pub forge_id: Option<String>,
    pub solution: Option<String>,
    pub project: Option<String>,
    pub no_project: Option<bool>,
}

/// Where one repository goes: both `None` for no project, both set otherwise.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Placement {
    pub solution: Option<String>,
    pub project: Option<String>,
}

impl Placement {
    pub const NONE: Placement = Placement { solution: None, project: None };

    pub fn filed(&self) -> bool {
        self.project.is_some()
    }
}

/// What [`ImportMapping::place`] decided; `refusal` is why the import would refuse it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub placement: Placement,
    pub refusal: Option<String>,
}

/// The rules, validated.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ImportMapping {
    pub rules: Vec<Rule>,
}

impl ImportMapping {
    /// `ImportMapping.of`: a rule names a namespace or a repository and not both, names something to change, and is
    /// the only rule for what it names. `None` entries are rules the request left empty.
    pub fn of(raw: Option<Vec<Option<Rule>>>) -> Result<ImportMapping, Refused> {
        let Some(raw) = raw.filter(|raw| !raw.is_empty()) else {
            return Ok(ImportMapping::default());
        };
        if raw.len() > MAX_RULES {
            return Err(Refused(format!("At most {MAX_RULES} mapping rules per import.")));
        }
        let mut rules = Vec::new();
        let mut named = HashSet::new();
        for rule in raw {
            let Some(rule) = rule else {
                return Err(Refused("A mapping rule is empty.".into()));
            };
            let mut namespace = trimmed_or_none(rule.namespace_path.as_deref());
            let mut forge_id = trimmed_or_none(rule.forge_id.as_deref());
            if namespace.is_none() == forge_id.is_none() {
                return Err(Refused(
                    "A mapping rule names a namespacePath or a forgeId, not both and not neither.".into(),
                ));
            }
            if let Some(path) = namespace {
                namespace = Some(
                    bounded_text::within(
                        strip_slashes(&path),
                        DiscoveredRepository::PATH_LENGTH,
                        "A mapping rule's namespacePath",
                    )?
                    .to_owned(),
                );
            } else if let Some(id) = forge_id {
                forge_id = Some(
                    bounded_text::within(&id, DiscoveredRepository::FORGE_ID_LENGTH, "A mapping rule's forgeId")?
                        .to_owned(),
                );
            }
            let no_project = rule.no_project == Some(true);
            let solution = rule.solution.as_deref().map(|raw| name(raw, "A solution name")).transpose()?;
            let project = rule.project.as_deref().map(|raw| name(raw, "A project name")).transpose()?;
            let what = match (&namespace, &forge_id) {
                (Some(namespace), _) => format!("namespace {namespace}"),
                (None, Some(id)) => format!("repository {id}"),
                (None, None) => String::new(),
            };
            if no_project && (solution.is_some() || project.is_some()) {
                return Err(Refused(format!("The rule for {what} files into no project and names one: choose.")));
            }
            if !no_project && solution.is_none() && project.is_none() {
                return Err(Refused(format!(
                    "The rule for {what} changes nothing: name a solution, a project, or no project."
                )));
            }
            let key = match (&namespace, &forge_id) {
                (Some(namespace), _) => format!("n:{}", java::to_lower_root(namespace)),
                (None, Some(id)) => format!("r:{id}"),
                (None, None) => String::new(),
            };
            if !named.insert(key) {
                return Err(Refused(format!("Two mapping rules name {what}.")));
            }
            rules.push(Rule { namespace_path: namespace, forge_id, solution, project, no_project: Some(no_project) });
        }
        Ok(ImportMapping { rules })
    }

    /// The proposal for a repository, before any rule.
    pub fn proposed(kind: ForgeKind, namespace_path: &str, name: &str, personal: bool) -> Placement {
        if personal {
            return Placement::NONE;
        }
        let namespace = strip_slashes(namespace_path);
        if namespace.is_empty() {
            return Placement::NONE;
        }
        match kind {
            ForgeKind::Gitlab => match namespace.split_once('/') {
                None => Placement { solution: Some(namespace.to_owned()), project: Some(namespace.to_owned()) },
                Some((top, rest)) => Placement { solution: Some(top.to_owned()), project: Some(rest.to_owned()) },
            },
            ForgeKind::Github => Placement { solution: Some(namespace.to_owned()), project: Some(name.to_owned()) },
        }
    }

    /// Where the repository goes once the rules are applied, or a refusal naming what is missing.
    pub fn place(&self, kind: ForgeKind, forge_id: &str, namespace_path: &str, name: &str, personal: bool) -> Outcome {
        let mut placed = ImportMapping::proposed(kind, namespace_path, name, personal);
        let namespace = java::to_lower_root(strip_slashes(namespace_path));
        let mut covering: Vec<&Rule> = self
            .rules
            .iter()
            .filter(|rule| rule.namespace_path.as_deref().is_some_and(|rule_path| covers(rule_path, &namespace)))
            .collect();
        // A stable sort by length in UTF-16 units, as `Comparator.comparingInt(String::length)` sorts.
        covering.sort_by_key(|rule| rule.namespace_path.as_deref().map_or(0, java::utf16_len));
        for rule in covering {
            placed = apply(placed, rule);
        }
        if let Some(own) = self.rules.iter().find(|rule| rule.forge_id.as_deref() == Some(forge_id)) {
            placed = apply(placed, own);
        }
        if let (Some(project), None) = (&placed.project, &placed.solution) {
            let refusal = format!("A project belongs to a solution: name the solution of project \"{project}\".");
            return Outcome { placement: placed, refusal: Some(refusal) };
        }
        if let (Some(solution), None) = (&placed.solution, &placed.project) {
            let refusal = format!(
                "A repository is filed into a project of solution \"{solution}\": name the project, or choose no \
                 project."
            );
            return Outcome { placement: placed, refusal: Some(refusal) };
        }
        let refusal = bounded_text::too_long(placed.solution.as_deref(), NAME_LENGTH, "The solution name")
            .or_else(|| bounded_text::too_long(placed.project.as_deref(), NAME_LENGTH, "The project name"));
        Outcome { placement: placed, refusal }
    }
}

fn covers(rule_namespace: &str, namespace: &str) -> bool {
    let rule = java::to_lower_root(rule_namespace);
    namespace == rule || namespace.starts_with(&format!("{rule}/"))
}

fn apply(placed: Placement, rule: &Rule) -> Placement {
    if rule.no_project == Some(true) {
        return Placement::NONE;
    }
    Placement { solution: rule.solution.clone().or(placed.solution), project: rule.project.clone().or(placed.project) }
}

fn name(raw: &str, what: &str) -> Result<String, Refused> {
    bounded_text::required(Some(raw), NAME_LENGTH, what)
}

/// `Texts.trimmedOrNull`.
fn trimmed_or_none(value: Option<&str>) -> Option<String> {
    value.map(java::trim).filter(|value| !value.is_empty()).map(str::to_owned)
}

fn strip_slashes(value: &str) -> &str {
    java::trim(value).trim_matches('/')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn placed(solution: &str, project: &str) -> Placement {
        Placement { solution: Some(solution.into()), project: Some(project.into()) }
    }

    #[test]
    fn the_proposal_per_forge() {
        assert_eq!(
            ImportMapping::proposed(ForgeKind::Gitlab, "acme/backend/payments", "api", false),
            placed("acme", "backend/payments")
        );
        assert_eq!(ImportMapping::proposed(ForgeKind::Gitlab, "/acme/", "api", false), placed("acme", "acme"));
        assert_eq!(ImportMapping::proposed(ForgeKind::Github, "acme", "api", false), placed("acme", "api"));
        assert_eq!(ImportMapping::proposed(ForgeKind::Gitlab, "jdoe", "api", true), Placement::NONE);
    }

    #[test]
    fn the_most_specific_word_on_each_field_wins() {
        let mapping = ImportMapping::of(Some(vec![
            Some(Rule {
                namespace_path: Some("acme/backend".into()),
                project: Some("Backend".into()),
                ..Rule::default()
            }),
            Some(Rule { namespace_path: Some("ACME".into()), solution: Some("Acme".into()), ..Rule::default() }),
            Some(Rule { forge_id: Some("7".into()), no_project: Some(true), ..Rule::default() }),
        ]))
        .unwrap();
        assert_eq!(
            mapping.place(ForgeKind::Gitlab, "1", "acme/backend/payments", "api", false).placement,
            placed("Acme", "Backend")
        );
        assert_eq!(
            mapping.place(ForgeKind::Gitlab, "7", "acme/backend/payments", "api", false).placement,
            Placement::NONE
        );
        let personal = ImportMapping::of(Some(vec![Some(Rule {
            namespace_path: Some("jdoe".into()),
            project: Some("Mine".into()),
            ..Rule::default()
        })]))
        .unwrap();
        assert_eq!(
            personal.place(ForgeKind::Gitlab, "1", "jdoe", "x", true).refusal.as_deref(),
            Some("A project belongs to a solution: name the solution of project \"Mine\".")
        );
    }

    #[test]
    fn rules_are_refused_in_words() {
        let refused = |rule: Rule| ImportMapping::of(Some(vec![Some(rule)])).unwrap_err().0;
        assert_eq!(
            refused(Rule { solution: Some("x".into()), ..Rule::default() }),
            "A mapping rule names a namespacePath or a forgeId, not both and not neither."
        );
        assert_eq!(
            refused(Rule { forge_id: Some("1".into()), ..Rule::default() }),
            "The rule for repository 1 changes nothing: name a solution, a project, or no project."
        );
        assert_eq!(
            refused(Rule {
                forge_id: Some("1".into()),
                no_project: Some(true),
                project: Some("p".into()),
                ..Rule::default()
            }),
            "The rule for repository 1 files into no project and names one: choose."
        );
        let twice = ImportMapping::of(Some(vec![
            Some(Rule { namespace_path: Some("a".into()), solution: Some("x".into()), ..Rule::default() }),
            Some(Rule { namespace_path: Some("/A/".into()), solution: Some("y".into()), ..Rule::default() }),
        ]))
        .unwrap_err()
        .0;
        assert_eq!(twice, "Two mapping rules name namespace A.");
        assert_eq!(ImportMapping::of(Some(vec![None])).unwrap_err().0, "A mapping rule is empty.");
    }
}
