//! `vectispire-rust/golden/deferred/`: every recording not replayed yet, and why — **a list that only shrinks**, one
//! file per module whose port ends its lines (`<module>.txt`), and `_<name>.txt` for what no module's port ends
//! ([`crate::shrinking`]: each file's own `ceiling N`).
//!
//! One line per reason a recording waits, in three forms:
//!
//! ```text
//! route  GET /api/v1/teams                     | access — Phase 1, task 1.7
//! golden api.FooRoutesTest/bar--003-GET-api_v1_x | the backlog figures are IssuesStandIn's zeros until Phase 3
//! outside GET /actuator/health                 | not an operation of the contract: the binary's (2.11)
//! ```
//!
//! A `route` line covers every recording of that operation, a `golden` line one recording of a route the router
//! serves, an `outside` line a request no operation answers. Every recording of a test that passed when recorded
//! must be replayed green or covered; a line that covers nothing, or only recordings that now replay green, is
//! stale and fails, so the list cannot keep a reason that has gone. Each file's `ceiling` holds its length: lowered
//! in the commit that removes lines, never raised to make room. A line is one line of the whole list: the same line in
//! two files is listed twice.

use std::collections::{BTreeMap, BTreeSet};

use crate::document::Document;
use crate::recorded::format::Recording;
use crate::recorded::replay::{Outcome, Replayed};
use crate::shrinking::{ListFile, against_ceiling, count, deferred_dir, read_dir};

/// The list, read.
#[derive(Clone, Debug, Default)]
pub struct Deferred {
    pub routes: BTreeMap<(String, String), String>,
    pub goldens: BTreeMap<String, String>,
    pub outside: BTreeMap<(String, String), String>,
    /// Each file's label, lines and ceiling — or what is wrong with its ceiling.
    pub files: Vec<(String, usize, Result<usize, String>)>,
}

impl Deferred {
    /// The committed list: every file of `golden/deferred/`.
    ///
    /// # Panics
    /// When a committed file is malformed or the directory cannot be read — which `tests/recorded.rs` shows first.
    #[must_use]
    pub fn committed() -> Deferred {
        read_dir(&deferred_dir())
            .map_err(|problem| vec![problem])
            .and_then(|files| Deferred::parse_files(&files))
            .unwrap_or_else(|problems| panic!("golden/deferred/: {}", problems.join("; ")))
    }

    /// Reads one text of lines, without a ceiling — a test's.
    pub fn parse(text: &str) -> Result<Deferred, Vec<String>> {
        let mut out = Deferred::default();
        let mut problems = Vec::new();
        let lines: Vec<(usize, &str)> = text
            .lines()
            .enumerate()
            .map(|(index, line)| (index.saturating_add(1), line.trim()))
            .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
            .collect();
        out.read_lines("line", &lines, &mut problems);
        if problems.is_empty() { Ok(out) } else { Err(problems) }
    }

    /// Reads the files of the list, each with its ceiling; every malformed or repeated line is a problem.
    pub fn parse_files(files: &[ListFile]) -> Result<Deferred, Vec<String>> {
        let mut out = Deferred::default();
        let mut problems = Vec::new();
        for file in files {
            let read = count(file);
            let before = out.len();
            out.read_lines(&file.label, &read.lines, &mut problems);
            out.files.push((file.label.clone(), out.len().saturating_sub(before), read.ceiling));
        }
        if problems.is_empty() { Ok(out) } else { Err(problems) }
    }

    fn read_lines(&mut self, label: &str, lines: &[(usize, &str)], problems: &mut Vec<String>) {
        for (at, line) in lines {
            let at = format!("{label} {at}");
            let Some((what, reason)) = line.split_once(" | ") else {
                problems.push(format!("{at}: no ` | reason`"));
                continue;
            };
            // The line is trimmed first: a reason of white space alone leaves no ` | ` to split on, and is refused above.
            let reason = reason.trim().to_owned();
            let mut words = what.split_whitespace();
            let repeated = match (words.next(), words.next(), words.next(), words.next()) {
                (Some("route"), Some(method), Some(path), None) => {
                    self.routes.insert((method.to_owned(), path.to_owned()), reason).is_some()
                }
                (Some("outside"), Some(method), Some(path), None) => {
                    self.outside.insert((method.to_owned(), path.to_owned()), reason).is_some()
                }
                (Some("golden"), Some(name), None, None) => self.goldens.insert(name.to_owned(), reason).is_some(),
                _ => {
                    problems
                        .push(format!("{at}: not `route METHOD /path`, `golden class/file` or `outside METHOD /path`"));
                    continue;
                }
            };
            if repeated {
                problems.push(format!("{at}: listed twice"));
            }
        }
    }

    /// How many lines the list holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.routes.len().saturating_add(self.goldens.len()).saturating_add(self.outside.len())
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The reason a recording waits, if the list gives one.
    #[must_use]
    pub fn reason(&self, name: &str, method: &str, path: &str, route: Option<&(String, String)>) -> Option<&str> {
        if let Some(reason) = self.goldens.get(name) {
            return Some(reason);
        }
        match route {
            Some(route) => self.routes.get(route).map(String::as_str),
            None => self.outside.get(&(method.to_owned(), path.to_owned())).map(String::as_str),
        }
    }
}

/// The list against the contract: a `route` line names a documented operation, and each file is at its ceiling.
#[must_use]
pub fn check_list(deferred: &Deferred, document: &Document) -> Vec<String> {
    let mut problems = Vec::new();
    let routes = document.routes();
    for route in deferred.routes.keys() {
        if !routes.contains(route) {
            problems.push(format!("route {} {}: not an operation of openapi.json", route.0, route.1));
        }
    }
    for (label, lines, ceiling) in &deferred.files {
        match ceiling {
            Ok(ceiling) => problems.extend(against_ceiling(label, *lines, *ceiling)),
            Err(problem) => problems.push(problem.clone()),
        }
    }
    problems
}

/// What a recording is, before anything is replayed: whether a test that passed recorded it, its route, and whether
/// the router serves that route.
#[derive(Clone, Debug)]
pub struct Listed {
    pub name: String,
    pub method: String,
    pub path: String,
    pub route: Option<(String, String)>,
    pub served: bool,
}

/// Every recording of a passed test, read and placed — what is owed without replaying anything.
pub fn listed(
    recording: &Recording,
    document: &Document,
    served: &BTreeSet<(String, String)>,
) -> Result<Vec<Listed>, String> {
    let mut out = Vec::new();
    for test in recording.tests.iter().filter(|test| test.outcome == "passed") {
        for file in &test.files {
            let exchange = recording.exchange(test, file).map_err(|error| error.to_string())?;
            let request = &exchange.request;
            let route = document
                .find(&request.method, &request.path)
                .map(|operation| (operation.method.to_ascii_uppercase(), operation.path.clone()));
            let is_served = route.as_ref().is_some_and(|route| served.contains(route));
            out.push(Listed {
                name: test.golden_name(file),
                method: request.method.clone(),
                path: request.path.clone(),
                route,
                served: is_served,
            });
        }
    }
    Ok(out)
}

/// Every recording of a route not served, or outside the contract, is covered by a line; a recording of a served
/// route is owed a replay unless a line covers it. Lines nothing needs are stale. `outcomes` are the replay's, when
/// one ran: then a served recording that replayed green must not be covered by its own line, and one that did not
/// must be covered.
#[must_use]
pub fn coverage(deferred: &Deferred, listed: &[Listed], outcomes: Option<&[Replayed]>) -> Vec<String> {
    let mut problems = Vec::new();
    let mut used_routes: BTreeMap<&(String, String), (usize, usize)> = BTreeMap::new();
    let mut used_goldens = BTreeSet::new();
    let mut used_outside = BTreeSet::new();
    let outcome_of = |name: &str| {
        outcomes.and_then(|all| all.iter().find(|replayed| replayed.name == name)).map(|replayed| &replayed.outcome)
    };
    for recording in listed {
        let golden_line = deferred.goldens.contains_key(&recording.name);
        if golden_line {
            used_goldens.insert(recording.name.as_str());
        }
        match &recording.route {
            None => {
                let key = (recording.method.clone(), recording.path.clone());
                if deferred.outside.contains_key(&key) {
                    used_outside.insert(key);
                } else if !golden_line {
                    problems.push(format!(
                        "{}: {} {} reaches no operation and no `outside` line covers it",
                        recording.name, recording.method, recording.path
                    ));
                }
            }
            Some(route) => {
                let route_line = deferred.routes.get_key_value(route).map(|(key, _)| key);
                let green = matches!(outcome_of(&recording.name), Some(Outcome::Green));
                if let Some(key) = route_line {
                    let counts = used_routes.entry(key).or_insert((0, 0));
                    counts.0 = counts.0.saturating_add(1);
                    if green {
                        counts.1 = counts.1.saturating_add(1);
                    }
                }
                if !recording.served {
                    if route_line.is_none() && !golden_line {
                        problems.push(format!(
                            "{}: {} {} is not served and no line says why it waits",
                            recording.name, route.0, route.1
                        ));
                    }
                    continue;
                }
                let Some(outcomes) = outcomes else {
                    continue;
                };
                match outcomes.iter().find(|replayed| replayed.name == recording.name).map(|replayed| &replayed.outcome)
                {
                    None => {
                        problems.push(format!("{}: of a served route, and the replay did not run it", recording.name))
                    }
                    Some(Outcome::Green) if golden_line => problems.push(format!(
                        "{}: replays green — remove its line from golden/deferred/ and lower that file's ceiling",
                        recording.name
                    )),
                    Some(Outcome::Green | Outcome::NotAnOracle) => {}
                    Some(other) if !golden_line && route_line.is_none() => {
                        problems.push(format!("{}: {}", recording.name, describe(other)));
                    }
                    Some(_) => {}
                }
            }
        }
    }
    for (route, reason) in &deferred.routes {
        match used_routes.get(route) {
            None => problems.push(format!("route {} {} ({reason}): no recording needs this line", route.0, route.1)),
            Some((total, green)) if outcomes.is_some() && total == green => problems
                .push(format!("route {} {}: every recording of it replays green — remove the line", route.0, route.1)),
            Some(_) => {}
        }
    }
    for name in deferred.goldens.keys() {
        if !used_goldens.contains(name.as_str()) {
            problems.push(format!("golden {name}: no such recording of a passed test"));
        }
    }
    for key in deferred.outside.keys() {
        if !used_outside.contains(key) {
            problems.push(format!("outside {} {}: no recording needs this line", key.0, key.1));
        }
    }
    problems
}

/// One outcome, in a sentence.
#[must_use]
pub fn describe(outcome: &Outcome) -> String {
    match outcome {
        Outcome::Green => "replays green".to_owned(),
        Outcome::Differs(lines) => format!("differs from Java's:\n      {}", lines.join("\n      ")),
        Outcome::Unreplayable(reason) => format!("cannot be replayed: {reason}"),
        Outcome::Played => "played in Java's place".to_owned(),
        Outcome::NotPlayed(reason) => format!("not played: {reason}"),
        Outcome::NotAnOracle => "of a test that did not pass when recorded".to_owned(),
    }
}
