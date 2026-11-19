//! Matching a version to its life cycle, and the verdict that follows — Java's `LifeCycle`, `Version` and `Purls`.
//!
//! Pure: everything that can genuinely go wrong here — a version prefix compared wrongly, a date read askew, a purl
//! carrying its architecture — is testable with no network. [`crate::end_of_life`] only fetches the catalog and caches
//! it.

use std::collections::HashMap;

use serde_json::Value;
use time::Date;
use time::macros::format_description;
use vectispire_domain::java;
use vectispire_domain::sbom::Artifact;
use vectispire_domain::severity::Severity;

/// `DEFAULT_WARNING_WINDOW`, in days.
pub const DEFAULT_WARNING_DAYS: i64 = 180;

/// A version's component that `Integer.parseInt` would refuse: past `i32::MAX`. Java throws, and the step it runs in
/// is reported absent; so is it here.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("For input string: \"{0}\"")]
pub struct Unreadable(pub String);

/// A product release, as the catalog publishes it. `maintained` false with no date is the abandoned-product case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub name: Option<String>,
    pub eol_from: Option<Date>,
    pub eol: Option<bool>,
    pub maintained: Option<bool>,
    pub latest: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Product {
    pub name: Option<String>,
    pub releases: Vec<Release>,
}

/// The verdict on a cycle. Absent means comfortably supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    pub severity: Severity,
    pub eol_date: Option<Date>,
}

/// What a SBOM offers the lookup. `purl` is none for a distribution: a Syft SBOM carries **no purl for the operating
/// system itself**, even though that is the most useful answer for a container image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub product: String,
    pub version: String,
    pub label: String,
    pub purl: Option<String>,
}

/// `Version`: a version's numeric components. `"9.7 (Plow)"` becomes `[9, 7]` and `"3.12.1-rc1"` `[3, 12, 1]`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Version(Vec<i32>);

impl Version {
    fn parse(version: Option<&str>) -> Result<Version, Unreadable> {
        let trimmed = java::trim(version.unwrap_or(""));
        let cleaned = trimmed.split(' ').next().unwrap_or("");
        let mut parts = Vec::new();
        for chunk in cleaned.split('.') {
            let digits: String = chunk.chars().take_while(char::is_ascii_digit).collect();
            if digits.is_empty() {
                // Stop rather than skip: after a non-numeric chunk the remaining numbers no longer line up
                // positionally with the cycle's, and comparing them would match the wrong one.
                break;
            }
            parts.push(digits.parse::<i32>().map_err(|_| Unreadable(digits.clone()))?);
        }
        Ok(Version(parts))
    }

    /// Whether this version names a cycle `other` belongs to — **component by component, never by string prefix**:
    /// "3.14" starts with "3.1", and a prefix test files Python 3.14 under the 3.1 cycle.
    fn is_cycle_of(&self, other: &Version) -> bool {
        !self.0.is_empty() && self.0.len() <= other.0.len() && other.0.starts_with(&self.0)
    }
}

/// `matchRelease`: the cycle a version belongs to; the longest matching cycle wins, so a product publishing both "8"
/// and "8.1" resolves to the more specific one.
pub fn match_release<'a>(product: &'a Product, version: &str) -> Result<Option<&'a Release>, Unreadable> {
    let wanted = Version::parse(Some(version))?;
    let mut best: Option<(&Release, usize)> = None;
    for release in &product.releases {
        let cycle = Version::parse(release.name.as_deref())?;
        if cycle.is_cycle_of(&wanted) && best.is_none_or(|(_, length)| cycle.0.len() > length) {
            best = Some((release, cycle.0.len()));
        }
    }
    Ok(best.map(|(release, _)| release))
}

/// `assess`: **a cycle already past its end is high** — nothing will be fixed tomorrow; an end date still ahead,
/// inside the window, is medium; beyond the window nothing is reported, since flagging a version supported for another
/// three years teaches people to filter this whole finding type out. Not maintained with no date is high: the deadline
/// has no date, which is worse, not milder.
pub fn assess(release: &Release, today: Date, warning_days: i64) -> Option<Verdict> {
    let eol_date = release.eol_from;
    if release.eol == Some(true) || eol_date.is_some_and(|date| date <= today) {
        return Some(Verdict { severity: Severity::High, eol_date });
    }
    if let Some(date) = eol_date {
        // Julian days, so the difference is whole days and cannot overflow two dates' range.
        let days_left = i64::from(date.to_julian_day()).saturating_sub(i64::from(today.to_julian_day()));
        if (0..=warning_days).contains(&days_left) {
            return Some(Verdict { severity: Severity::Medium, eol_date });
        }
    }
    if release.maintained == Some(false) && eol_date.is_none() {
        return Some(Verdict { severity: Severity::High, eol_date: None });
    }
    None
}

/// `recommendedVersion`: the most recent maintained release — what "fix this" means here.
pub fn recommended_version(product: &Product) -> Option<String> {
    product.releases.iter().filter(|release| release.maintained == Some(true) && release.eol != Some(true)).find_map(
        |release| release.latest.clone().or_else(|| release.name.clone()).filter(|name| !java::is_blank(name)),
    )
}

/// `parseDate`: an ISO date from the catalog, its first ten characters.
pub fn parse_date(value: Option<&str>) -> Option<Date> {
    let value = value?;
    if value.encode_utf16().count() < 10 {
        return None;
    }
    let day: String = value.chars().take(10).collect();
    Date::parse(&day, format_description!("[year]-[month]-[day]")).ok()
}

/// `parseProduct`: by hand rather than bound by field names — `isEol` against `eol`, and a `latest` that is an object
/// on the wire — so that a change of spelling cannot silently produce a product with no releases.
pub fn parse_product(payload: &Value) -> Option<Product> {
    let result = payload.get("result").filter(|result| result.is_object())?;
    let releases = match result.get("releases") {
        Some(Value::Array(items)) => items.iter().collect(),
        Some(Value::Object(fields)) => fields.values().collect(),
        _ => Vec::new(),
    };
    Some(Product {
        name: text_or_none(result, "name"),
        releases: releases
            .into_iter()
            .map(|release| Release {
                name: text_or_none(release, "name"),
                eol_from: parse_date(text_or_none(release, "eolFrom").as_deref()),
                eol: release.get("isEol").and_then(Value::as_bool),
                maintained: release.get("isMaintained").and_then(Value::as_bool),
                latest: release.get("latest").and_then(|latest| text_or_none(latest, "name")),
            })
            .collect(),
    })
}

fn text_or_none(node: &Value, field: &str) -> Option<String> {
    node.get(field).and_then(Value::as_str).filter(|text| !java::is_blank(text)).map(str::to_owned)
}

/// `JsonNode.asText("")`: a value node's text, nothing for the rest.
fn as_text(node: Option<&Value>) -> String {
    match node {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Number(number)) => number.to_string(),
        Some(Value::Bool(flag)) => flag.to_string(),
        _ => String::new(),
    }
}

/// `parseIdentifierIndex`: the catalog's purl index, `normalized purl → product name` — one request, close to nine
/// hundred matches, and no table to maintain by hand.
pub fn parse_identifier_index(payload: &Value) -> HashMap<String, String> {
    let Some(Value::Array(entries)) = payload.get("result") else {
        return HashMap::new();
    };
    let mut index = HashMap::new();
    for entry in entries {
        let identifier = as_text(entry.get("identifier"));
        let product = as_text(entry.get("product").and_then(|product| product.get("name")));
        let product = java::trim(&product);
        if !identifier.is_empty() && !product.is_empty() {
            index.insert(normalize_purl(Some(&identifier)), product.to_owned());
        }
    }
    index
}

/// `packageCandidates`: the SBOM packages that match a product in the catalog.
pub fn package_candidates(artifacts: &[Artifact], index: &HashMap<String, String>) -> Vec<Candidate> {
    if index.is_empty() {
        return Vec::new();
    }
    artifacts
        .iter()
        .filter_map(|artifact| {
            let purl = artifact.purl.as_ref()?;
            let version = artifact.version.as_ref().filter(|version| !java::is_blank(version))?;
            let product = index.get(&normalize_purl(Some(purl)))?;
            Some(Candidate {
                product: product.clone(),
                version: java::trim(version).to_owned(),
                label: artifact.name.clone().unwrap_or_else(|| product.clone()),
                purl: Some(purl.clone()),
            })
        })
        .collect()
}

/// `Purls.normalize`: `pkg:type/namespace/name`, lowercase, with no version and no qualifiers — a SBOM purl carries
/// both where a catalog's identifiers carry neither, and comparing them as they are matches nothing.
pub fn normalize_purl(purl: Option<&str>) -> String {
    let mut value = java::trim(purl.unwrap_or(""));
    for separator in ['?', '#'] {
        if let Some((before, _)) = value.split_once(separator) {
            value = before;
        }
    }
    if let Some(at) = value.rfind('@').filter(|at| *at > 0) {
        value = value.get(..at).unwrap_or(value);
    }
    java::to_lower_root(value).trim_end_matches('/').to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::date;

    const TODAY: Date = date!(2026 - 08 - 13);

    fn release(name: &str, eol_from: Option<Date>, eol: Option<bool>, maintained: Option<bool>) -> Release {
        Release { name: Some(name.to_owned()), eol_from, eol, maintained, latest: None }
    }

    fn product(releases: Vec<Release>) -> Product {
        Product { name: Some("p".to_owned()), releases }
    }

    fn matched(product: &Product, version: &str) -> Option<String> {
        match_release(product, version).unwrap().and_then(|release| release.name.clone())
    }

    #[test]
    fn never_matches_by_prefix() {
        let python = product(vec![
            release("3.1", Some(date!(2012 - 04 - 09)), Some(true), Some(false)),
            release("3.14", Some(date!(2030 - 10 - 01)), Some(false), Some(true)),
        ]);
        assert_eq!(matched(&python, "3.14.0").as_deref(), Some("3.14"));
    }

    #[test]
    fn the_longest_cycle_wins_and_the_first_of_equals() {
        let both = product(vec![release("8", None, None, Some(true)), release("8.1", None, None, Some(true))]);
        assert_eq!(matched(&both, "8.1.3").as_deref(), Some("8.1"));
        let reversed = product(vec![release("8.1", None, None, Some(true)), release("8", None, None, Some(true))]);
        assert_eq!(matched(&reversed, "8.1.3").as_deref(), Some("8.1"));
        let twice = Product {
            releases: vec![
                Release { latest: Some("first".to_owned()), ..release("8", None, None, None) },
                Release { latest: Some("second".to_owned()), ..release("8", None, None, None) },
            ],
            ..product(Vec::new())
        };
        assert_eq!(match_release(&twice, "8.0").unwrap().and_then(|r| r.latest.clone()).as_deref(), Some("first"));
    }

    #[test]
    fn tolerates_decorated_versions_and_matches_nothing_rather_than_the_nearest() {
        for (version, cycle) in [("9.7 (Plow)", "9.7"), ("3.12.1-rc1", "3.12"), ("22.04", "22.04")] {
            assert_eq!(
                matched(&product(vec![release(cycle, None, Some(false), Some(true))]), version).as_deref(),
                Some(cycle)
            );
        }
        assert_eq!(matched(&product(vec![release("9", None, Some(false), Some(true))]), "10.2"), None);
        assert_eq!(matched(&product(vec![release("9", None, None, None)]), "v9"), None, "nothing numeric, no cycle");
        assert_eq!(matched(&product(vec![release("", None, None, None)]), "9"), None, "an empty cycle matches nothing");
        assert_eq!(
            matched(&product(vec![release("9.x.1", None, None, None)]), "9.2"),
            Some("9.x.1".to_owned()),
            "stops at x"
        );
    }

    #[test]
    fn a_component_past_an_int_is_unreadable() {
        let nine = product(vec![release("9", None, None, None)]);
        assert_eq!(match_release(&nine, "99999999999.1"), Err(Unreadable("99999999999".to_owned())));
    }

    #[test]
    fn the_verdicts() {
        let high = |r: &Release, days| assess(r, TODAY, days).map(|verdict| verdict.severity);
        assert_eq!(
            high(&release("8", Some(date!(2024 - 01 - 01)), Some(false), Some(false)), 180),
            Some(Severity::High)
        );
        assert_eq!(
            high(&release("8", Some(TODAY), Some(false), Some(true)), 180),
            Some(Severity::High),
            "ending today"
        );
        assert_eq!(
            high(&release("9", Some(date!(2026 - 10 - 01)), Some(false), Some(true)), 180),
            Some(Severity::Medium)
        );
        assert_eq!(high(&release("10", Some(date!(2030 - 01 - 01)), Some(false), Some(true)), 180), None);
        assert_eq!(
            assess(&release("1", None, None, Some(false)), TODAY, 180),
            Some(Verdict { severity: Severity::High, eol_date: None })
        );
        assert_eq!(high(&release("7", None, Some(true), Some(false)), 180), Some(Severity::High));
        assert_eq!(high(&release("11", None, Some(false), Some(true)), 180), None);
        let later = release("10", Some(date!(2027 - 06 - 01)), Some(false), Some(true));
        assert_eq!(high(&later, 180), None);
        assert_eq!(high(&later, 365), Some(Severity::Medium));
        let edge = release("10", Some(date!(2026 - 08 - 23)), Some(false), Some(true));
        assert_eq!(high(&edge, 10), Some(Severity::Medium), "the window's last day included");
        assert_eq!(high(&edge, 9), None);
    }

    #[test]
    fn the_recommendation() {
        let p = product(vec![
            Release { latest: Some("12.4".to_owned()), ..release("12", None, Some(false), Some(true)) },
            Release { latest: Some("11.9".to_owned()), ..release("11", None, Some(true), Some(false)) },
        ]);
        assert_eq!(recommended_version(&p).as_deref(), Some("12.4"));
        assert_eq!(recommended_version(&product(vec![release("1", None, Some(true), Some(false))])), None);
        assert_eq!(recommended_version(&product(vec![release("13", None, None, Some(true))])).as_deref(), Some("13"));
        let eol_maintained = product(vec![release("14", None, Some(true), Some(true))]);
        assert_eq!(recommended_version(&eol_maintained), None);
    }

    #[test]
    fn purls_name_the_product() {
        for (purl, expected) in [
            ("pkg:rpm/redhat/openssl@3.5.1?arch=x86_64", "pkg:rpm/redhat/openssl"),
            ("pkg:npm/lodash@4.17.21", "pkg:npm/lodash"),
            ("PKG:NPM/Lodash", "pkg:npm/lodash"),
            ("pkg:deb/debian/bash@5.2#subpath", "pkg:deb/debian/bash"),
            (" pkg:npm/%40scope/thing@1#x?y ", "pkg:npm/%40scope/thing"),
            ("pkg:golang/example.com/mod//", "pkg:golang/example.com/mod"),
            ("@1.0", "@1.0"),
        ] {
            assert_eq!(normalize_purl(Some(purl)), expected, "{purl}");
        }
    }

    #[test]
    fn dates_and_payloads() {
        assert_eq!(parse_date(Some("2026-10-01T00:00:00Z")), Some(date!(2026 - 10 - 01)));
        assert_eq!(parse_date(Some("2026-10-1")), None);
        assert_eq!(parse_date(Some("not a date")), None);
        assert_eq!(parse_date(None), None);
        let payload = serde_json::json!({"result": {"name": "python", "releases": [
            {"name": "3.14", "eolFrom": "2030-10-01", "isEol": false, "isMaintained": true, "latest": {"name": "3.14.2"}},
            {"name": " ", "isEol": "yes", "latest": "3.0"}
        ]}});
        let parsed = parse_product(&payload).unwrap();
        assert_eq!(parsed.name.as_deref(), Some("python"));
        assert_eq!(
            parsed.releases,
            [
                Release {
                    name: Some("3.14".to_owned()),
                    eol_from: Some(date!(2030 - 10 - 01)),
                    eol: Some(false),
                    maintained: Some(true),
                    latest: Some("3.14.2".to_owned()),
                },
                Release { name: None, eol_from: None, eol: None, maintained: None, latest: None },
            ]
        );
        assert_eq!(parse_product(&serde_json::json!({"result": []})), None);
        let index = parse_identifier_index(&serde_json::json!({"result": [
            {"identifier": "pkg:pypi/django@1", "product": {"name": " django "}},
            {"identifier": "", "product": {"name": "nothing"}},
            {"identifier": "pkg:npm/x", "product": {}}
        ]}));
        assert_eq!(index, HashMap::from([("pkg:pypi/django".to_owned(), "django".to_owned())]));
        assert!(parse_identifier_index(&serde_json::json!({"result": {}})).is_empty());
    }

    #[test]
    fn package_candidates_need_a_purl_a_version_and_an_index() {
        let index = HashMap::from([("pkg:pypi/django".to_owned(), "django".to_owned())]);
        let artifact = |name: Option<&str>, version: Option<&str>, purl: Option<&str>| Artifact {
            name: name.map(str::to_owned),
            version: version.map(str::to_owned),
            purl: purl.map(str::to_owned),
            licenses: Vec::new(),
        };
        let artifacts = [
            artifact(Some("Django"), Some(" 4.2.1 "), Some("pkg:pypi/django@4.2.1")),
            artifact(None, Some("4.2"), Some("pkg:pypi/Django@4.2")),
            artifact(Some("x"), Some(" "), Some("pkg:pypi/django@1")),
            artifact(Some("x"), Some("1"), None),
            artifact(Some("flask"), Some("2"), Some("pkg:pypi/flask@2")),
        ];
        assert_eq!(
            package_candidates(&artifacts, &index),
            [
                Candidate {
                    product: "django".to_owned(),
                    version: "4.2.1".to_owned(),
                    label: "Django".to_owned(),
                    purl: Some("pkg:pypi/django@4.2.1".to_owned()),
                },
                Candidate {
                    product: "django".to_owned(),
                    version: "4.2".to_owned(),
                    label: "django".to_owned(),
                    purl: Some("pkg:pypi/Django@4.2".to_owned()),
                },
            ]
        );
        assert!(package_candidates(&artifacts, &HashMap::new()).is_empty());
    }
}
