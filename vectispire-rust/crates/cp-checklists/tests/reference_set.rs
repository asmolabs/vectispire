//! The checklists vocabulary against `ChecklistsReferenceSetTest`'s answers for `reference/checklists/inputs.json`:
//! the normalised text, item keys and content digests, every refusal's sentence, the pairing of two versions, the
//! contact profiles and the reminders, the scopes and patterns, Maven's order and ranges, every rule's canonical
//! form and digest, every evaluation's evidence — byte for byte, since each is stored, signed or read by a person.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};
use vectispire_cp_checklists::answer::{AnswerAuthor, AnswerWords, ChecklistAnswer, GivenAnswer};
use vectispire_cp_checklists::coverage_scope::CoverageScope;
use vectispire_cp_checklists::evaluation::evaluate;
use vectispire_cp_checklists::item::{
    ChecklistColumn, ChecklistItem, EvidenceKind, EvidenceRequirement, ItemKey, ItemWords,
};
use vectispire_cp_checklists::measurement::{Measurement, MeasurementOutcome, NoDataReason, Reconciliation};
use vectispire_cp_checklists::pairing::{Change, ManualPair, VersionPairing};
use vectispire_cp_checklists::reminder::{self, Gap, Line, ProfileLines, Unreached};
use vectispire_cp_checklists::rule::{ChecklistRule, Kind};
use vectispire_cp_checklists::suite_pattern::SuitePattern;
use vectispire_cp_checklists::tool_scope::{BUILT_IN_PREFIX, BUILT_IN_TYPES, ToolScope};
use vectispire_cp_checklists::{Failure, Refused, contacts, source_languages, text};
use vectispire_domain::checklists::facts::{
    Component, CoverageReport, Imported, IssueCount, MeasurementFacts, PackageCounts, Packages, PluginRun, PluginRuns,
    PluginState, ReviewFacts, ScanLanguages, Scanned, ScopeFacts, Suite, TestReport,
};
use vectispire_domain::checklists::{ChangeReviewEvidence, Look, Source};
use vectispire_domain::instant::Instant;
use vectispire_domain::language::Language;
use vectispire_domain::maven_version::{MavenVersion, MavenVersionRange};

fn s(value: &Value) -> Option<&str> {
    value.as_str()
}

fn refused(refusal: &Refused) -> Value {
    json!({ "refused": refusal.0 })
}

fn failure(failure: &Failure) -> Value {
    match failure {
        Failure::Refused(refusal) => refused(refusal),
        Failure::Defect(defect) => json!({ "illegal": defect.0 }),
    }
}

fn answered<T>(result: Result<T, Refused>, value: impl FnOnce(T) -> Value) -> Value {
    result.map_or_else(|refusal| refused(&refusal), value)
}

struct Differences(Vec<String>);

impl Differences {
    fn check(&mut self, what: String, java: &Value, rust: &Value) {
        if java != rust {
            self.0.push(format!("{what}:\n  java {java}\n  rust {rust}"));
        }
    }
}

fn vocabulary() -> Value {
    let wire = |names: Vec<String>| Value::from(names);
    let mut built_in: Vec<String> =
        BUILT_IN_TYPES.iter().map(|kind| format!("{BUILT_IN_PREFIX}{}", kind.wire_name())).collect();
    built_in.sort();
    json!({
        "answers": wire(ChecklistAnswer::ALL.iter().map(|value| value.wire_name().to_owned()).collect()),
        "authors": wire(AnswerAuthor::ALL.iter().map(|value| value.wire_name().to_owned()).collect()),
        "outcomes": wire(MeasurementOutcome::ALL.iter().map(|value| value.wire_name().to_owned()).collect()),
        "reasons": wire(NoDataReason::ALL.iter().map(|value| value.wire_name().to_owned()).collect()),
        "reconciliations": wire(Reconciliation::ALL.iter().map(|value| value.wire_name().to_owned()).collect()),
        "evidenceKinds": wire(EvidenceKind::ALL.iter().map(|value| value.wire_name().to_owned()).collect()),
        "ruleKinds": wire(Kind::ALL.iter().map(|value| value.wire_name().to_owned()).collect()),
        "sources": wire(Source::ALL.iter().map(|value| value.wire_name().to_owned()).collect()),
        "gaps": wire(Gap::ALL.iter().map(|gap| format!("{}: {}", gap.wire_name(), gap.words())).collect()),
        "columns": wire(ChecklistColumn::ALL.iter().map(|column| format!("{}{}", column.wire_name(), if column.required() { "!" } else { "" })).collect()),
        "sourceLanguages": wire(Language::all().map(|language| format!("{}{}", language.wire_name(), if source_languages::is_source(language) { "" } else { " (not source)" })).collect()),
        "builtInScopes": built_in,
    })
}

fn requirement(input: &Value) -> Result<EvidenceRequirement, Refused> {
    let kind = EvidenceKind::parse(s(&input["kind"]))?;
    EvidenceRequirement::new(kind, input["validity"].as_i64().map(|months| i32::try_from(months).unwrap()))
}

fn key(input: &Value) -> Result<ItemKey, Refused> {
    if input.get("id").is_some() {
        ItemKey::from_id(s(&input["id"]))
    } else {
        ItemKey::from_control(s(&input["control"]))
    }
}

fn item(input: &Value) -> Result<ChecklistItem, Failure> {
    let words = ItemWords {
        domain: s(&input["domain"]),
        objective: s(&input["objective"]),
        control: s(&input["control"]),
        contact: s(&input["contact"]),
        kpi: s(&input["kpi"]),
    };
    let key = key(&input["key"])?;
    let evidence = requirement(&input["evidence"])?;
    ChecklistItem::new(
        key,
        i32::try_from(input["position"].as_i64().unwrap()).unwrap(),
        &words,
        i32::try_from(input["row"].as_i64().unwrap()).unwrap(),
        evidence,
        s(&input["boundRule"]).map(str::to_owned),
    )
}

fn pairing(input: &Value) -> Result<Value, Failure> {
    let items = |list: &Value| list.as_array().unwrap().iter().map(item).collect::<Result<Vec<_>, _>>();
    let previous = items(&input["previous"])?;
    let next = items(&input["next"])?;
    let by_hand = input["byHand"]
        .as_array()
        .unwrap()
        .iter()
        .map(|pair| Ok(ManualPair { added: key(&pair[0])?, removed: key(&pair[1])? }))
        .collect::<Result<Vec<_>, Refused>>()?;
    let pairing = VersionPairing::of(&previous, &next, &by_hand)?;
    let changes: Vec<Value> = pairing
        .changes
        .iter()
        .map(|change| match change {
            Change::Unchanged { previous, next } => json!({"change": "unchanged", "previous": previous.row, "next": next.row, "key": next.key.value()}),
            Change::Changed { previous, next, paired_by_hand } => json!({"change": "changed", "previous": previous.row, "next": next.row, "key": next.key.value(), "byHand": paired_by_hand}),
            Change::Added { next } => json!({"change": "added", "next": next.row, "key": next.key.value()}),
            Change::Removed { previous } => json!({"change": "removed", "previous": previous.row, "key": previous.key.value()}),
        })
        .collect();
    Ok(json!({ "changes": changes, "next": pairing.next.iter().map(|item| item.key.value()).collect::<Vec<_>>() }))
}

fn profiles(list: &[contacts::Profile]) -> Value {
    Value::from(list.iter().map(|profile| json!([profile.key, profile.label])).collect::<Vec<_>>())
}

fn rule(rule: &ChecklistRule) -> Value {
    let canonical = rule.canonical();
    let rereads = ChecklistRule::from_canonical(&canonical).map(|back| back.canonical() == canonical).unwrap_or(false);
    json!({ "kind": rule.kind().wire_name(), "canonical": canonical, "digest": rule.digest(), "rereads": rereads })
}

// ------------------------------------------------------------------ the facts, as inputs.json writes them

fn look(node: &Value) -> Option<Look> {
    let parts = node.as_array()?;
    Some(Look {
        source: Source::from_wire_name(parts[0].as_str().unwrap()).unwrap(),
        id: parts[1].as_i64().unwrap(),
        at: Instant::parse_java(parts[2].as_str().unwrap()).unwrap(),
        digest: parts[3].as_str().map(str::to_owned),
    })
}

fn languages(node: &Value) -> Option<BTreeSet<Language>> {
    Some(node.as_array()?.iter().map(|name| Language::from_wire_name(name.as_str().unwrap()).unwrap()).collect())
}

fn by_repository<T>(node: &Value, read: impl Fn(&Value) -> T) -> BTreeMap<i64, T> {
    node.as_object()
        .into_iter()
        .flatten()
        .map(|(repository, value)| (repository.parse().unwrap(), read(value)))
        .collect()
}

fn int(node: &Value) -> i32 {
    i32::try_from(node.as_i64().unwrap()).unwrap()
}

fn state(name: &str) -> PluginState {
    match name {
        "PRODUCED" => PluginState::Produced,
        "NOT_APPLICABLE" => PluginState::NotApplicable,
        "ABSENT" => PluginState::Absent,
        "REFUSED_UNSIGNED" => PluginState::RefusedUnsigned,
        "REFUSED_SIGNATURE_UNVERIFIED" => PluginState::RefusedSignatureUnverified,
        "REFUSED_REGISTRY_AUTHENTICATION_REQUIRED" => PluginState::RefusedRegistryAuthenticationRequired,
        other => panic!("no plugin state {other}"),
    }
}

fn scope_facts(node: &Value) -> ScopeFacts {
    if let Some(scanned) = node.get("scanned") {
        return ScopeFacts::Scanned(Scanned {
            newest_producing: look(&scanned["newest"]),
            sbom_stored: scanned["sbom"].as_bool().unwrap(),
            recorded_within_age: int(&scanned["recorded"]),
            unrecorded_within_age: int(&scanned["unrecorded"]),
        });
    }
    if let Some(plugin) = node.get("plugin") {
        return ScopeFacts::PluginRuns(PluginRuns {
            within_age: plugin["runs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|run| PluginRun {
                    scan: look(&run["scan"]).unwrap(),
                    state: state(run["state"].as_str().unwrap()),
                    reads: languages(&run["reads"]),
                })
                .collect(),
            scans_within_age: int(&plugin["scans"]),
            named_before: plugin["namedBefore"].as_bool().unwrap(),
        });
    }
    let imported = &node["imported"];
    ScopeFacts::Imported(Imported {
        newest_producing: look(&imported["newest"]),
        unrecorded_within_age: imported["unrecorded"].as_bool().unwrap(),
    })
}

fn pair_part(node: &Value, index: usize) -> Option<i64> {
    node.as_array().map(|pair| pair[index].as_i64().unwrap())
}

fn packages(node: &Value) -> Packages {
    match node {
        Value::Null => Packages::NotRead,
        Value::String(_) => Packages::Unrecorded,
        Value::Object(_) => Packages::NotKept(node["notKept"].as_str().unwrap().to_owned()),
        _ => Packages::Kept(
            node.as_array()
                .unwrap()
                .iter()
                .map(|part| PackageCounts {
                    path: part[0].as_str().unwrap().to_owned(),
                    lines_covered: part[1].as_i64().unwrap(),
                    lines_total: part[2].as_i64().unwrap(),
                    branches_covered: part[3].as_i64(),
                    branches_total: part[4].as_i64(),
                })
                .collect(),
        ),
    }
}

fn review(node: &Value) -> ReviewFacts {
    if let Some(unlinked) = node.get("unlinked") {
        return ReviewFacts::Unlinked {
            look: look(&unlinked["look"]).unwrap(),
            why: unlinked["why"].as_str().unwrap().to_owned(),
        };
    }
    if let Some(unreadable) = node.get("unreadable") {
        return ReviewFacts::Unreadable {
            look: look(&unreadable["look"]).unwrap(),
            why: unreadable["why"].as_str().unwrap().to_owned(),
        };
    }
    let read = &node["read"];
    ReviewFacts::Read {
        look: look(&read["look"]).unwrap(),
        evidence: ChangeReviewEvidence::read(read["evidence"].as_str().unwrap()).unwrap(),
    }
}

fn facts(input: &Value) -> MeasurementFacts {
    MeasurementFacts {
        repository_ids: input["repositories"].as_array().unwrap().iter().map(|id| id.as_i64().unwrap()).collect(),
        scopes: input["scopes"]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(key, value)| (key.clone(), by_repository(value, scope_facts)))
            .collect(),
        counts: input["counts"]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(key, value)| {
                (
                    key.clone(),
                    by_repository(value, |list| {
                        list.as_array()
                            .unwrap()
                            .iter()
                            .map(|count| IssueCount {
                                severity: count[0].as_str().unwrap().to_owned(),
                                state: count[1].as_str().unwrap().to_owned(),
                                count: count[2].as_i64().unwrap(),
                            })
                            .collect()
                    }),
                )
            })
            .collect(),
        scheduled: by_repository(&input["scheduled"], |value| value.as_bool().unwrap()),
        coverage: by_repository(&input["coverage"], |report| CoverageReport {
            look: look(&report["look"]).unwrap(),
            lines_covered: report["lines"][0].as_i64().unwrap(),
            lines_total: report["lines"][1].as_i64().unwrap(),
            branches_covered: pair_part(&report["branches"], 0),
            branches_total: pair_part(&report["branches"], 1),
            packages: packages(&report["packages"]),
        }),
        tests: by_repository(&input["tests"], |report| TestReport {
            look: look(&report["look"]).unwrap(),
            suites: report["suites"]
                .as_array()
                .unwrap()
                .iter()
                .map(|suite| Suite {
                    name: suite[0].as_str().map(str::to_owned),
                    tests: int(&suite[1]),
                    failures: int(&suite[2]),
                    errors: int(&suite[3]),
                    skipped: int(&suite[4]),
                })
                .collect(),
        }),
        components: by_repository(&input["components"], |list| {
            list.as_array()
                .unwrap()
                .iter()
                .map(|component| Component {
                    name: component[0].as_str().map(str::to_owned),
                    version: component[1].as_str().map(str::to_owned),
                    purl: component[2].as_str().map(str::to_owned),
                })
                .collect()
        }),
        languages: by_repository(&input["languages"], |recorded| ScanLanguages {
            detected: languages(&recorded["detected"]),
            sast_rules: languages(&recorded["sast"]),
        }),
        reviews: by_repository(&input["reviews"], review),
    }
}

#[test]
fn the_checklists_domain_answers_as_the_java_side_answers() {
    let inputs = vectispire_testkit::read_json("checklists/inputs.json");
    let answers = vectispire_testkit::read_json("checklists/java-answers.json");
    let differences = std::cell::RefCell::new(Differences(Vec::new()));
    let each = |section: &str, rust: Vec<Value>| {
        let java = answers[section].as_array().unwrap_or_else(|| panic!("no {section} in the answers"));
        assert_eq!(java.len(), rust.len(), "{section}: as many answers as inputs");
        for (index, (java, rust)) in java.iter().zip(&rust).enumerate() {
            let input =
                inputs.get(section).and_then(|list| list.get(index)).map(|input| input.to_string()).unwrap_or_default();
            differences.borrow_mut().check(
                format!("{section}[{index}] {}", input.chars().take(160).collect::<String>()),
                java,
                rust,
            );
        }
    };
    let list = |section: &str| inputs[section].as_array().unwrap().clone();

    each("texts", list("texts").iter().map(|text| Value::from(text::normalize(s(text)))).collect());
    each(
        "itemIds",
        list("itemIds").iter().map(|id| answered(ItemKey::from_id(s(id)), |key| Value::from(key.value()))).collect(),
    );
    each(
        "controls",
        list("controls")
            .iter()
            .map(|control| answered(ItemKey::from_control(s(control)), |key| Value::from(key.value())))
            .collect(),
    );
    each(
        "answers",
        list("answers")
            .iter()
            .map(|value| {
                answered(
                    ChecklistAnswer::parse(s(value)),
                    |answer| json!({"wire": answer.wire_name(), "requiresComment": answer.requires_comment()}),
                )
            })
            .collect(),
    );
    each(
        "authors",
        list("authors")
            .iter()
            .map(|value| json!({"isSystem": AnswerAuthor::is_system(s(value)), "stored": AnswerAuthor::of_stored(s(value)).map(AnswerAuthor::wire_name)}))
            .collect(),
    );
    each(
        "answerWords",
        list("answerWords")
            .iter()
            .map(|input| {
                answered(AnswerWords::new(s(&input["yes"]), s(&input["no"]), s(&input["notApplicable"])), |mapped| {
                    let answer_of: Vec<Value> = input["words"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|word| mapped.answer_of(s(word)).map(ChecklistAnswer::wire_name).into())
                        .collect();
                    let word: Vec<Value> = ChecklistAnswer::ALL
                        .iter()
                        .map(|answer| answered(mapped.word(*answer), Value::from))
                        .collect();
                    let written: Vec<&str> = ChecklistAnswer::ALL.iter().map(|answer| mapped.written(*answer)).collect();
                    json!({"offersNotApplicable": mapped.offers_not_applicable(), "answerOf": answer_of, "word": word, "written": written})
                })
            })
            .collect(),
    );
    each(
        "givenAnswers",
        list("givenAnswers")
            .iter()
            .map(|input| {
                let offered = AnswerWords::new(
                    Some("Oui"),
                    Some("Non"),
                    input["offersNotApplicable"].as_bool().unwrap().then_some("Sans objet"),
                )
                .unwrap();
                answered(
                    ChecklistAnswer::parse(s(&input["value"]))
                        .and_then(|value| GivenAnswer::of(value, s(&input["comment"]), &offered)),
                    |given| json!({"value": given.value.wire_name(), "comment": given.comment}),
                )
            })
            .collect(),
    );
    each(
        "evidence",
        list("evidence")
            .iter()
            .map(|input| answered(requirement(input), |requirement| Value::from(requirement.canonical())))
            .collect(),
    );
    each(
        "items",
        list("items")
            .iter()
            .map(|input| {
                item(input).map_or_else(
                    |refusal| failure(&refusal),
                    |item| {
                        json!({"key": item.key.value(), "domain": item.domain, "objective": item.objective, "control": item.control,
                            "contact": item.contact, "kpi": item.kpi, "contentDigest": item.content_digest()})
                    },
                )
            })
            .collect(),
    );
    each(
        "pairings",
        list("pairings").iter().map(|input| pairing(input).unwrap_or_else(|refusal| failure(&refusal))).collect(),
    );

    let cells = list("contacts");
    each(
        "contacts",
        cells
            .iter()
            .map(|cell| json!({"profiles": profiles(&contacts::of(s(cell))), "keys": s(cell).map(contacts::keys_of).unwrap_or_default()}))
            .collect(),
    );
    differences.borrow_mut().check(
        "allContacts".to_owned(),
        &answers["allContacts"],
        &profiles(&contacts::of_all(cells.iter().filter_map(Value::as_str))),
    );
    each("contactKeys", list("contactKeys").iter().map(|name| Value::from(contacts::key_of(s(name)))).collect());

    let message = |message: reminder::Message| json!({"subject": message.subject, "body": message.body});
    let to_contact: Vec<Value> = inputs["reminders"]["toContact"]
        .as_array()
        .unwrap()
        .iter()
        .map(|input| {
            let profiles: Vec<ProfileLines> = input["profiles"]
                .as_array()
                .unwrap()
                .iter()
                .map(|profile| ProfileLines {
                    project_id: profile["projectId"].as_i64().unwrap(),
                    project_name: profile["projectName"].as_str().unwrap().to_owned(),
                    profile: profile["profile"].as_str().unwrap().to_owned(),
                    lines: profile["lines"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|line| Line {
                            position: int(&line["position"]),
                            control: line["control"].as_str().unwrap().to_owned(),
                        })
                        .collect(),
                })
                .collect();
            message(reminder::to_contact(
                s(&input["name"]),
                &profiles,
                input["week"].as_str().unwrap(),
                s(&input["publicUrl"]),
            ))
        })
        .collect();
    let to_ciso: Vec<Value> = inputs["reminders"]["toCiso"]
        .as_array()
        .unwrap()
        .iter()
        .map(|input| {
            let unreached: Vec<Unreached> = input["unreached"]
                .as_array()
                .unwrap()
                .iter()
                .map(|profile| Unreached {
                    project_id: profile["projectId"].as_i64().unwrap(),
                    project_name: profile["projectName"].as_str().unwrap().to_owned(),
                    profile: profile["profile"].as_str().unwrap().to_owned(),
                    lines: int(&profile["lines"]),
                    gap: Gap::ALL
                        .into_iter()
                        .find(|gap| gap.wire_name().to_uppercase() == profile["gap"].as_str().unwrap())
                        .unwrap(),
                })
                .collect();
            message(reminder::to_ciso(&unreached, input["week"].as_str().unwrap(), s(&input["publicUrl"])))
        })
        .collect();
    differences.borrow_mut().check(
        "reminders".to_owned(),
        &answers["reminders"],
        &json!({"toContact": to_contact, "toCiso": to_ciso}),
    );

    each(
        "scopes",
        list("scopes")
            .iter()
            .map(|input| {
                answered(ToolScope::parse(s(input)), |scope| json!({"key": scope.key(), "kind": scope.kind_name()}))
            })
            .collect(),
    );
    each(
        "coverageScopes",
        list("coverageScopes")
            .iter()
            .map(|input| {
                let patterns = |node: &Value| node.as_array().map(|list| list.iter().map(|value| value.as_str().map(str::to_owned)).collect::<Vec<_>>());
                let include = patterns(&input["include"]);
                let exclude = patterns(&input["exclude"]);
                answered(CoverageScope::new(include.as_deref(), exclude.as_deref()), |scope| {
                    let matches: Vec<bool> = input
                        .get("paths")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .map(|path| scope.matches(path.as_str().unwrap()))
                        .collect();
                    json!({"include": scope.include, "exclude": scope.exclude, "describe": scope.describe(), "matches": matches})
                })
            })
            .collect(),
    );
    each(
        "suites",
        list("suites")
            .iter()
            .map(|input| {
                let pattern = SuitePattern::of(input["pattern"].as_str().unwrap());
                Value::from(
                    input["names"].as_array().unwrap().iter().map(|name| pattern.matches(s(name))).collect::<Vec<_>>(),
                )
            })
            .collect(),
    );
    each(
        "versions",
        list("versions")
            .iter()
            .map(|pair| {
                let order =
                    MavenVersion::of(pair[0].as_str().unwrap()).cmp(&MavenVersion::of(pair[1].as_str().unwrap()));
                Value::from(order as i32)
            })
            .collect(),
    );
    each(
        "ranges",
        list("ranges")
            .iter()
            .map(|input| {
                let spec = s(&input["spec"]);
                let parsed = answered(MavenVersionRange::parse(spec), |range| {
                    let contains: Vec<bool> =
                        input["versions"].as_array().unwrap().iter().map(|version| range.contains(version.as_str().unwrap())).collect();
                    json!({"written": range.to_string(), "contains": contains})
                });
                json!({"looksLikeRange": MavenVersionRange::looks_like_range(spec), "readable": MavenVersionRange::read(spec).is_some(), "parsed": parsed})
            })
            .collect(),
    );
    each(
        "rules",
        list("rules")
            .iter()
            .map(|input| answered(ChecklistRule::parse_text(s(input)), |parsed| rule(&parsed)))
            .collect(),
    );
    each(
        "storedRules",
        list("storedRules")
            .iter()
            .map(|input| {
                ChecklistRule::from_canonical(input.as_str().unwrap())
                    .map_or_else(|refusal| failure(&refusal), |parsed| rule(&parsed))
            })
            .collect(),
    );
    each(
        "evaluations",
        list("evaluations")
            .iter()
            .map(|input| {
                let text = input["rule"].as_str().unwrap();
                let parsed = if input["stored"].as_bool().unwrap() {
                    ChecklistRule::from_canonical(text).unwrap()
                } else {
                    ChecklistRule::parse_text(Some(text)).unwrap()
                };
                let measured = evaluate(
                    &parsed,
                    &facts(&input["facts"]),
                    Instant::parse_java(input["now"].as_str().unwrap()).unwrap(),
                )
                .map_or_else(
                    |defect| json!({"illegal": defect.0}),
                    |measured| {
                        let evidence = measured.evidence_json();
                        let rereads =
                            Measurement::read(&evidence).map(|back| back.evidence_json() == evidence).unwrap_or(false);
                        json!({"evidence": evidence, "digest": measured.evidence_digest(), "rereads": rereads})
                    },
                );
                json!({"name": input["name"], "measured": measured})
            })
            .collect(),
    );
    each(
        "storedMeasurements",
        list("storedMeasurements")
            .iter()
            .map(|input| {
                Measurement::read(input.as_str().unwrap())
                    .map_or_else(|defect| json!({"illegal": defect.0}), |read| Value::from(read.evidence_json()))
            })
            .collect(),
    );
    each(
        "storedReviews",
        list("storedReviews")
            .iter()
            .map(|input| {
                ChangeReviewEvidence::read(input.as_str().unwrap())
                    .map_or_else(|defect| json!({"illegal": defect.0}), |read| Value::from(read.json()))
            })
            .collect(),
    );

    let mut reconciliations = Vec::new();
    let given = std::iter::once(None).chain(ChecklistAnswer::ALL.into_iter().map(Some));
    for answer in given {
        for outcome in std::iter::once(None).chain(MeasurementOutcome::ALL.into_iter().map(Some)) {
            reconciliations.push(Value::from(Reconciliation::of(answer, outcome).wire_name()));
        }
    }
    each("reconciliations", reconciliations);
    differences.borrow_mut().check("vocabulary".to_owned(), &answers["vocabulary"], &vocabulary());

    let differences = differences.into_inner().0;
    assert!(
        differences.is_empty(),
        "{} difference(s) from the Java side:\n{}",
        differences.len(),
        differences.join("\n")
    );
}
