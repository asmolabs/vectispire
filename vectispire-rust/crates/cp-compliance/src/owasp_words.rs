//! The language an OWASP document is written in — Java's `AdviceLanguage` — and the grid's reasons in it, as
//! `OwaspReportWords.reason` words them: English is the domain's own sentence, French is said here.

use vectispire_domain::java;
use vectispire_domain::owasp_coverage::{CoverageLine, CoverageReason, Gap, GapCount, ReasonCode};

use crate::error::ComplianceError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdviceLanguage {
    English,
    French,
}

impl AdviceLanguage {
    const CODES: [(&'static str, AdviceLanguage); 2] =
        [("en", AdviceLanguage::English), ("fr", AdviceLanguage::French)];

    /// `AdviceLanguage.parse`: absent or blank is English; otherwise trimmed, lower-cased, one of the codes.
    pub fn parse(code: Option<&str>) -> Result<AdviceLanguage, ComplianceError> {
        let Some(code) = code.filter(|code| !java::is_blank(code)) else {
            return Ok(AdviceLanguage::English);
        };
        let asked = java::to_lower_root(java::trim(code));
        AdviceLanguage::CODES.iter().find(|(known, _)| *known == asked).map(|(_, language)| *language).ok_or_else(
            || {
                let codes: Vec<&str> = AdviceLanguage::CODES.iter().map(|(known, _)| *known).collect();
                ComplianceError::Invalid(format!("language must be one of {}.", codes.join(", ")))
            },
        )
    }
}

/// `OwaspReportWords.reason`: the line's `because` in English, its reason said in French otherwise.
pub fn reason(line: &CoverageLine, language: AdviceLanguage) -> String {
    if language != AdviceLanguage::French {
        return line.because.clone();
    }
    let reason = &line.reason;
    let types = reason.types.iter().map(|wire| french_type(wire)).collect::<Vec<_>>().join(", ");
    match reason.code {
        ReasonCode::NoScanner => {
            "Aucun scanner de ce déploiement ne produit de constat dans cette catégorie.".to_owned()
        }
        ReasonCode::CodeAnalysisOff => {
            "L'analyse de code est désactivée, ou seule la règle livrée avec ce produit est installée.".to_owned()
        }
        ReasonCode::DetectionOff => {
            format!("La détection est désactivée pour {types} : cette catégorie n'est donc pas mesurée.")
        }
        ReasonCode::DetectionAndCodeAnalysisOff => format!(
            "La détection est désactivée pour {types}, et l'analyse de code est désactivée ou seule la règle livrée \
             avec ce produit est installée : cette catégorie n'est donc pas mesurée."
        ),
        ReasonCode::OpenFindings => "Des constats ouverts sont placés ici par règle.".to_owned(),
        ReasonCode::NothingScanned => {
            "Rien n'a encore été scanné : aucun constat de cette catégorie ne pouvait exister.".to_owned()
        }
        ReasonCode::TargetKindNotExamined => format!(
            "Rien ici n'examine ce type de cible pour {types} : le scan d'une image ne lit que ses dépendances."
        ),
        ReasonCode::CodeAnalysisReadsRepositoriesOnly => {
            "Seule l'analyse de code place des constats ici, et elle lit les dépôts, pas les images.".to_owned()
        }
        ReasonCode::NoExaminableTargetInScope => format!(
            "Aucune cible de ce périmètre ne peut être examinée pour {types} : le scan d'une image ne lit que ses \
             dépendances, et ce périmètre ne contient aucun dépôt."
        ),
        ReasonCode::NoRepositoryInScope => {
            "Seule l'analyse de code place des constats ici, et ce périmètre ne contient aucun dépôt à lire.".to_owned()
        }
        ReasonCode::ExaminedNothingOpen => format!(
            "Examinée par {types} — le dernier scan de chaque cible concernée l'a examinée — sans rien d'ouvert."
        ),
        ReasonCode::CodeExaminedNothingOpen => "Examinée par l'analyse de code — le dernier scan de chaque dépôt \
                                                concerné l'a examinée — sans rien d'ouvert."
            .to_owned(),
        ReasonCode::TargetsNotExamined => unexamined(reason, "des cibles concernées", "examinée", "examinées", &types),
        ReasonCode::RepositoriesNotExamined => {
            unexamined(reason, "des dépôts concernés", "examiné", "examinés", "l'analyse de code")
        }
    }
}

fn unexamined(reason: &CoverageReason, which: &str, one: &str, many: &str, by: &str) -> String {
    let missing = reason.missing.unwrap_or(0);
    let why = reason.gaps.iter().map(french_gap).collect::<Vec<_>>().join(", ");
    // `String.valueOf` of a null `Long`.
    let applicable = reason.applicable.map_or_else(|| "null".to_owned(), |count| count.to_string());
    let verb = if missing == 1 { format!("n'a pas été {one}") } else { format!("n'ont pas été {many}") };
    format!(
        "{missing} {which} par cette catégorie ({applicable} au total) {verb} pour elle par {by} ({why}) : un zéro ici \
         ne serait pas un résultat."
    )
}

fn french_gap(gap: &GapCount) -> String {
    let count = gap.targets;
    let words = match gap.gap {
        Gap::NeverScanned if count == 1 => " n'a jamais terminé de scan",
        Gap::NeverScanned => " n'ont jamais terminé de scan",
        Gap::LastScanFailed => " dont le dernier scan a échoué",
        Gap::Unrecorded => " dont le dernier scan précède l'enregistrement de ce qu'il a examiné",
        Gap::StepAbsent => " dont le dernier scan n'a pas terminé cette étape",
        Gap::LanguagesUnrecorded => " dont le dernier scan n'a pas enregistré ses langages, ni ceux de ses règles",
        Gap::NoRuleForItsLanguages => " dans les langages desquels aucune règle installée ne déclare cette catégorie",
    };
    format!("{count}{words}")
}

/// The interface's names of the finding types (`issues.types.*`), lower-cased as they sit in a sentence.
fn french_type(wire: &str) -> &str {
    match wire {
        "vulnerability" => "vulnérabilité",
        "secret" => "secret exposé",
        "iac" => "configuration d'infrastructure",
        "eol" => "fin de support",
        "license" => "licence",
        "sast" => "code vulnérable",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_language_is_read_as_java_reads_it() {
        assert_eq!(AdviceLanguage::parse(None).ok(), Some(AdviceLanguage::English));
        assert_eq!(AdviceLanguage::parse(Some("  ")).ok(), Some(AdviceLanguage::English));
        assert_eq!(AdviceLanguage::parse(Some(" FR ")).ok(), Some(AdviceLanguage::French));
        assert_eq!(AdviceLanguage::parse(Some("en")).ok(), Some(AdviceLanguage::English));
        assert!(matches!(
            AdviceLanguage::parse(Some("de")),
            Err(ComplianceError::Invalid(message)) if message == "language must be one of en, fr."
        ));
    }

    #[test]
    fn an_unexamined_scope_is_counted_in_french() {
        let reason = CoverageReason {
            code: ReasonCode::RepositoriesNotExamined,
            types: vec!["sast".to_owned()],
            missing: Some(1),
            applicable: Some(3),
            gaps: vec![
                GapCount { gap: Gap::NeverScanned, targets: 1 },
                GapCount { gap: Gap::LastScanFailed, targets: 2 },
            ],
        };
        assert_eq!(
            unexamined(&reason, "des dépôts concernés", "examiné", "examinés", "l'analyse de code"),
            "1 des dépôts concernés par cette catégorie (3 au total) n'a pas été examiné pour elle par l'analyse de \
             code (1 n'a jamais terminé de scan, 2 dont le dernier scan a échoué) : un zéro ici ne serait pas un \
             résultat."
        );
        let several =
            CoverageReason { missing: Some(2), gaps: vec![GapCount { gap: Gap::NeverScanned, targets: 2 }], ..reason };
        assert!(
            unexamined(&several, "des cibles concernées", "examinée", "examinées", "vulnérabilité")
                .contains("n'ont pas été examinées pour elle par vulnérabilité (2 n'ont jamais terminé de scan)")
        );
    }
}
