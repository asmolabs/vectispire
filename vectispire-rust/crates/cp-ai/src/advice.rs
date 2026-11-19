//! `AiVulnerabilityAdvice`: the advisor's answer — what a model wrote, or what this product writes itself when no model
//! answers — and `AdviceLanguage`.
//!
//! **Nothing here that was not read.** What this product holds about a vulnerability is its component, the fix
//! recorded, the KEV listing and the EPSS score; the deterministic paragraphs say those, or say that they are unknown.
//! **No reachability goes in**: nothing computes it, and the exposure paragraph says it was not assessed. **Never
//! `not_affected` from here**: an exemption stays a person's decision, with a name on it.

use serde::Serialize;
use vectispire_cp_threatintel::status::{Exploitation, KevListing};
use vectispire_domain::java;

use crate::ecosystem;

/// `AdviceLanguage`: the language a model is asked to explain in — the reader's screen's, English when none is said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdviceLanguage {
    English,
    French,
}

impl AdviceLanguage {
    const ALL: [(AdviceLanguage, &'static str); 2] = [(AdviceLanguage::English, "en"), (AdviceLanguage::French, "fr")];

    /// The language's name as the prompt spells it — the prompt itself is English.
    pub fn english_name(self) -> &'static str {
        match self {
            AdviceLanguage::English => "English",
            AdviceLanguage::French => "French",
        }
    }

    /// `parse`: by its code, English when none is given; a code that is not one of these is refused, naming those that
    /// are.
    pub fn parse(code: Option<&str>) -> Result<AdviceLanguage, String> {
        let Some(code) = code.filter(|code| !java::is_blank(code)) else {
            return Ok(AdviceLanguage::English);
        };
        let asked = java::to_lower_root(java::trim(code));
        AdviceLanguage::ALL.iter().find(|(_, known)| *known == asked).map(|(language, _)| *language).ok_or_else(|| {
            format!(
                "language must be one of {}.",
                AdviceLanguage::ALL.iter().map(|(_, known)| *known).collect::<Vec<_>>().join(", ")
            )
        })
    }
}

/// `KevListing` as the wire names it.
fn kev_name(kev: KevListing) -> &'static str {
    match kev {
        KevListing::Listed => "LISTED",
        KevListing::NotListed => "NOT_LISTED",
        KevListing::Unknown => "UNKNOWN",
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemediationAdvice {
    pub fix_action: String,
    pub suggested_version: Option<String>,
    pub code_snippet_or_diff: String,
    pub cli_command: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VexSuggestion {
    pub status: String,
    pub justification: Option<String>,
    pub impact_statement: String,
    pub action_statement: String,
}

/// Set when this product wrote the prose itself; none when a model did — so a screen can rebuild the sentences in the
/// reader's language from exactly these values. **A none is "unknown"**, and a screen says so.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Deterministic {
    pub package_name: Option<String>,
    pub current_version: Option<String>,
    pub target_version: Option<String>,
    #[serde(serialize_with = "kev_wire")]
    pub kev: KevListing,
    pub exploit_probability: Option<f64>,
}

fn kev_wire<S: serde::Serializer>(kev: &KevListing, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(kev_name(*kev))
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AiVulnerabilityAdvice {
    pub identifier: String,
    pub title: String,
    pub summary_explanation: String,
    pub exploit_mechanics: String,
    pub exposure_assessment: String,
    pub remediation: RemediationAdvice,
    pub vex_suggestion: VexSuggestion,
    pub references: Vec<String>,
    pub deterministic: Option<Deterministic>,
}

/// `present`: trimmed, none when blank.
pub(crate) fn present(value: Option<&str>) -> Option<String> {
    value.filter(|value| !java::is_blank(value)).map(|value| java::trim(value).to_owned())
}

/// `generateDeterministic`: the explanation this product writes itself, when no model answers or none is configured.
/// `purl` names the ecosystem an upgrade command is written for; none, and no command is offered.
pub fn generate_deterministic(
    identifier: Option<&str>,
    package_name: Option<&str>,
    current_version: Option<&str>,
    fix_version: Option<&str>,
    purl: Option<&str>,
    exploitation: Option<Exploitation>,
) -> AiVulnerabilityAdvice {
    build(identifier, package_name, current_version, fix_version, purl, exploitation, true)
}

/// `forIdentifierAlone`: an identifier no issue the caller can see carries — what the feeds say, nothing about a
/// component, and **never `affected`**, even for a listed CVE: nothing shows the estate is.
pub fn for_identifier_alone(identifier: Option<&str>, exploitation: Option<Exploitation>) -> AiVulnerabilityAdvice {
    build(identifier, None, None, None, None, exploitation, false)
}

fn build(
    identifier: Option<&str>,
    package_name: Option<&str>,
    current_version: Option<&str>,
    fix_version: Option<&str>,
    purl: Option<&str>,
    exploitation: Option<Exploitation>,
    carried_by_an_issue: bool,
) -> AiVulnerabilityAdvice {
    let id = identifier.filter(|id| !java::is_blank(id)).unwrap_or("an unidentified vulnerability").to_owned();
    let pkg = present(package_name);
    let version = present(current_version);
    let target = present(fix_version);
    let known = exploitation.unwrap_or_else(Exploitation::unknown);
    let summary = match &pkg {
        None => format!("Vulnerability {id}: the affected component is unknown."),
        Some(pkg) => format!(
            "Vulnerability {id} is reported in component '{pkg}', version {}.",
            version.as_deref().unwrap_or("unknown")
        ),
    };
    let kev = match known.kev {
        KevListing::Listed => "Listed in the CISA KEV catalogue: exploitation in the wild has been reported.",
        KevListing::NotListed => "Not listed in the CISA KEV catalogue in use.",
        KevListing::Unknown => {
            "Exploitation in the wild is unknown: no synchronised CISA KEV catalogue answers for this identifier."
        }
    };
    let epss = match known.epss_score {
        None => "EPSS probability: unknown.".to_owned(),
        Some(score) => format!("EPSS probability: {}%.", percent(score)),
    };
    let fix_action = match (&target, &pkg) {
        (None, _) => "No fixed version is recorded for this vulnerability.".to_owned(),
        (Some(target), None) => format!("Upgrade the affected component to {target}."),
        (Some(target), Some(pkg)) => {
            format!("Upgrade '{pkg}' from version {} to {target}.", version.as_deref().unwrap_or("unknown"))
        }
    };
    // A command and a descriptor only for the ecosystem the purl names, with a fixed version known.
    let upgrade = ecosystem::upgrade_of(purl, target.as_deref());
    let vex_status =
        if carried_by_an_issue && known.kev == KevListing::Listed { "affected" } else { "under_investigation" };
    let (vex_impact, vex_action) = match &target {
        None => (
            format!("Vulnerability {id} is under analysis; no fixed version is recorded."),
            "No fixed version is recorded: follow the advisory for a mitigation.".to_owned(),
        ),
        Some(target) => (
            format!("Vulnerability {id} is under analysis so the upgrade to {target} can be planned."),
            format!("Apply the fix by upgrading to version {target}."),
        ),
    };
    AiVulnerabilityAdvice {
        title: match &pkg {
            None => format!("Analysis and remediation for {id}"),
            Some(pkg) => format!("Analysis and remediation for {id} in {pkg}"),
        },
        summary_explanation: summary,
        exploit_mechanics: format!("{kev} {epss}"),
        exposure_assessment: "EXPOSURE NOT ASSESSED: Vectispire does not analyse whether your code calls this \
                              component. Check whether any user flow reaches this library's functions."
            .to_owned(),
        remediation: RemediationAdvice {
            fix_action,
            suggested_version: target.clone(),
            code_snippet_or_diff: upgrade.as_ref().map(|upgrade| upgrade.descriptor.clone()).unwrap_or_default(),
            cli_command: upgrade.map(|upgrade| upgrade.command).unwrap_or_default(),
        },
        vex_suggestion: VexSuggestion {
            status: vex_status.to_owned(),
            justification: None,
            impact_statement: vex_impact,
            action_statement: vex_action,
        },
        references: references(identifier),
        deterministic: Some(Deterministic {
            package_name: pkg,
            current_version: version,
            target_version: target,
            kev: known.kev,
            exploit_probability: known.epss_score,
        }),
        identifier: id,
    }
}

/// `references`: NVD and FIRST describe CVEs only — a link built from a GHSA, or from a `VULN-42`, leads nowhere.
pub fn references(identifier: Option<&str>) -> Vec<String> {
    match identifier.filter(|identifier| Exploitation::names_a_cve(Some(identifier))) {
        None => Vec::new(),
        Some(cve) => vec![
            format!("https://nvd.nist.gov/vuln/detail/{}", java::to_upper_root(java::trim(cve))),
            "https://www.first.org/epss".to_owned(),
        ],
    }
}

/// `percent`: `BigDecimal.valueOf(probability * 100).setScale(3, HALF_UP).stripTrailingZeros().toPlainString()` —
/// three decimals at most; one wrote 0.0 % for most of FIRST's scores, measured, small, and not zero.
pub(crate) fn percent(probability: f64) -> String {
    let value = probability * 100.0;
    if !value.is_finite() {
        return value.to_string();
    }
    // The shortest decimal that reads back as the double — `Double.toString`'s digits, which `BigDecimal.valueOf` takes.
    let text = format!("{value}");
    let (negative, digits) = match text.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, text.as_str()),
    };
    let (whole, fraction) = digits.split_once('.').unwrap_or((digits, ""));
    let mut kept: Vec<u8> = whole.bytes().chain(fraction.bytes().chain(std::iter::repeat(b'0')).take(3)).collect();
    // HALF_UP: away from zero when the first dropped digit is five or more.
    if fraction.as_bytes().get(3).is_some_and(|digit| *digit >= b'5') {
        let mut carry = true;
        for digit in kept.iter_mut().rev() {
            if !carry {
                break;
            }
            if *digit == b'9' {
                *digit = b'0';
            } else {
                *digit = digit.saturating_add(1);
                carry = false;
            }
        }
        if carry {
            kept.insert(0, b'1');
        }
    }
    let split = kept.len().saturating_sub(3);
    let (whole, fraction) = kept.split_at(split);
    let whole = String::from_utf8_lossy(whole).trim_start_matches('0').to_owned();
    let fraction = String::from_utf8_lossy(fraction).trim_end_matches('0').to_owned();
    let whole = if whole.is_empty() { "0".to_owned() } else { whole };
    let magnitude = if fraction.is_empty() { whole } else { format!("{whole}.{fraction}") };
    // BigDecimal has no negative zero.
    if negative && magnitude.bytes().any(|digit| digit.is_ascii_digit() && digit != b'0') {
        format!("-{magnitude}")
    } else {
        magnitude
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_probability_as_a_percentage_to_three_decimals_at_most() {
        for (probability, expected) in [
            (0.975, "97.5"),
            (0.5, "50"),
            (0.0, "0"),
            (1.0, "100"),
            (0.00007, "0.007"),
            (0.0000049, "0"),
            (0.0000051, "0.001"),
            (0.123456, "12.346"),
            (0.9999996, "100"),
            (0.000015, "0.002"),
            (0.1, "10"),
        ] {
            assert_eq!(percent(probability), expected, "{probability}");
        }
    }

    #[test]
    fn the_language_is_one_of_the_interfaces() {
        assert_eq!(AdviceLanguage::parse(None), Ok(AdviceLanguage::English));
        assert_eq!(AdviceLanguage::parse(Some("  ")), Ok(AdviceLanguage::English));
        assert_eq!(AdviceLanguage::parse(Some(" FR ")), Ok(AdviceLanguage::French));
        assert_eq!(AdviceLanguage::parse(Some("de")), Err("language must be one of en, fr.".to_owned()));
    }

    #[test]
    fn an_identifier_alone_is_never_affected() {
        let listed = Some(Exploitation { kev: KevListing::Listed, epss_score: Some(0.975) });
        let alone = for_identifier_alone(Some("CVE-2021-44228"), listed);
        assert_eq!(alone.vex_suggestion.status, "under_investigation");
        assert_eq!(alone.summary_explanation, "Vulnerability CVE-2021-44228: the affected component is unknown.");
        assert_eq!(
            alone.exploit_mechanics,
            "Listed in the CISA KEV catalogue: exploitation in the wild has been reported. EPSS probability: 97.5%."
        );
        let carried = generate_deterministic(
            Some("CVE-2021-44228"),
            Some(" log4j-core "),
            Some("2.14.1"),
            Some("2.17.1"),
            Some("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"),
            listed,
        );
        assert_eq!(carried.vex_suggestion.status, "affected");
        assert_eq!(carried.title, "Analysis and remediation for CVE-2021-44228 in log4j-core");
        assert_eq!(carried.remediation.fix_action, "Upgrade 'log4j-core' from version 2.14.1 to 2.17.1.");
        assert_eq!(
            carried.remediation.cli_command,
            "mvn versions:use-dep-version -Dincludes=org.apache.logging.log4j:log4j-core -DdepVersion=2.17.1 \
             -DforceVersion=true"
        );
        assert_eq!(carried.vex_suggestion.action_statement, "Apply the fix by upgrading to version 2.17.1.");
    }

    #[test]
    fn nothing_known_is_said_as_unknown() {
        let advice = generate_deterministic(Some(" "), None, None, None, None, None);
        assert_eq!(advice.identifier, "an unidentified vulnerability");
        assert_eq!(
            advice.exploit_mechanics,
            "Exploitation in the wild is unknown: no synchronised CISA KEV catalogue answers for this identifier. \
             EPSS probability: unknown."
        );
        assert!(advice.references.is_empty());
        assert_eq!(
            references(Some(" cve-2021-44228 ")),
            ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "https://www.first.org/epss"]
        );
        assert!(references(Some("GHSA-xxxx-yyyy-zzzz")).is_empty());
        let upgrade_alone = generate_deterministic(Some("CVE-2021-1"), None, None, Some("2.0"), None, None);
        assert_eq!(upgrade_alone.remediation.fix_action, "Upgrade the affected component to 2.0.");
        assert_eq!(
            vectispire_domain::wire::to_wire_string(&upgrade_alone.deterministic),
            r#"{"packageName":null,"currentVersion":null,"targetVersion":"2.0","kev":"UNKNOWN","exploitProbability":null}"#
        );
    }
}
