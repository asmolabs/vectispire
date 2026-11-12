#!/usr/bin/env python3
"""Writes src/catalog.rs from reference/settings/catalog.json, the catalog as the Java side defines it.

Run it after the Java catalog changed and its reference set was regenerated (SettingsReferenceSetTest), then
review the diff: the rules that decide who may write a setting (`directs_credential`, `administrator_only`,
`governor_only`) are written as Java writes them, from the facts the file states, and `governs_security` is
an exhaustive match with no wildcard arm — a setting added to the catalog does not compile until the line
that answers the question has been read. `tests/reference_set.rs` fails while the two disagree.

    python3 crates/cp-settings/scripts/generate-catalog.py
"""
import json
import pathlib

here = pathlib.Path(__file__).resolve().parent
crate = here.parent
catalog = json.loads((crate / "../../reference/settings/catalog.json").read_text(encoding="utf-8"))

SECTIONS = ["ACCESS", "TRIAGE", "ENRICHMENT", "END_OF_LIFE", "SOURCE_CODE", "SCHEDULING", "REMEDIATION",
            "RETENTION", "NOTIFICATIONS", "LICENSES", "CHECKLISTS", "TICKETS", "MODEL_REVIEW"]


def camel(name):
    return "".join(part.capitalize() for part in name.split("_"))


def raw(text):
    hashes = "#"
    while ('"' + hashes) in text:
        hashes += "#"
    return f'r{hashes}"{text}"{hashes}'


section_labels = {}
for setting in catalog:
    section_labels[setting["section"]] = setting["sectionLabel"]
missing = [section for section in SECTIONS if section not in section_labels]
assert not missing, f"a section no setting is filed under has no label in the reference set: {missing}"

out = []
w = out.append
w("//! The settings catalog — `common.domain.settings.Setting`, every key, in the Java enum's order.")
w("//!")
w("//! **Generated from `reference/settings/catalog.json` by `scripts/generate-catalog.py`**, which the Java side")
w("//! writes (`SettingsReferenceSetTest`); `tests/reference_set.rs` fails while the two disagree. The labels and")
w("//! the help are the screen's words; the rest decides who may write a setting and whether the SOC hears of it.")
w("")
w("use crate::types::{Section, Sensitivity, SettingType};")
w("")
w("/// A setting the application exposes — and only one a service actually reads.")
w("#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]")
w("pub enum Setting {")
for s in catalog:
    w(f"    {camel(s['name'])},")
w("}")
w("")
w("/// What the catalog says of one setting.")
w("#[derive(Debug, Clone, Copy, PartialEq, Eq)]")
w("pub struct Definition {")
w("    pub key: &'static str,")
w("    pub setting_type: SettingType,")
w("    pub section: Section,")
w("    pub label: &'static str,")
w("    /// What this setting changes, and above all what it does not.")
w("    pub help: &'static str,")
w("    pub default_value: &'static str,")
w("    pub sensitivity: Sensitivity,")
w("}")
w("")
w("impl Setting {")
w(f"    /// Every setting, in the Java enum's order.")
w(f"    pub const ALL: [Setting; {len(catalog)}] = [")
for s in catalog:
    w(f"        Setting::{camel(s['name'])},")
w("    ];")
w("")
w("    /// The Java constant's name.")
w("    pub const fn name(self) -> &'static str {")
w("        match self {")
for s in catalog:
    w(f"            Setting::{camel(s['name'])} => \"{s['name']}\",")
w("        }")
w("    }")
w("")
w("    /// The setting's definition.")
w("    pub const fn definition(self) -> Definition {")
w("        match self {")
for s in catalog:
    w(f"            Setting::{camel(s['name'])} => Definition {{")
    w(f"                key: \"{s['key']}\",")
    w(f"                setting_type: SettingType::{camel(s['type'])},")
    w(f"                section: Section::{camel(s['section'])},")
    w(f"                label: {raw(s['label'])},")
    w(f"                help: {raw(s['help'])},")
    w(f"                default_value: {raw(s['defaultValue'])},")
    w(f"                sensitivity: Sensitivity::{camel(s['sensitivity'])},")
    w("            },")
w("        }")
w("    }")
w("")
w("    /// The credential this setting decides the destination of, if it decides one — **whoever may point a")
w("    /// credential somewhere must be allowed to hold it**: the tracker's base URL, project, user, CA and the")
w("    /// switch to a private host direct the tracker token; the OpenAI URL and the remote switch, the OpenAI key.")
w("    pub const fn directs_credential(self) -> Option<Setting> {")
w("        match self {")
groups = {}
for s in catalog:
    if s["directsCredential"]:
        groups.setdefault(s["directsCredential"], []).append(s["name"])
for target, names in groups.items():
    w("            " + " | ".join(f"Setting::{camel(n)}" for n in names) + f" => Some(Setting::{camel(target)}),")
w("            _ => None,")
w("        }")
w("    }")
w("")
w("    /// Whether only the platform governor may change it: every setting of the access, triage and checklist")
w("    /// sections — a rule, not a parameter — and the evidence window, which the roles the evidence judges do")
w("    /// not decide.")
w("    pub const fn governor_only(self) -> bool {")
w("        matches!(self.definition().section, Section::Access | Section::Triage | Section::Checklists)")
w("            || matches!(self, Setting::EvidenceRetentionDays)")
w("    }")
w("")
w("    /// Whether changing it changes what the deployment protects, and so is forwarded to the SOC. **No wildcard")
w("    /// arm**: a setting added to the catalog does not compile until whoever adds it has answered.")
w("    pub const fn governs_security(self) -> bool {")
w("        match self {")
true_names = [s["name"] for s in catalog if s["governsSecurity"]]
false_names = [s["name"] for s in catalog if not s["governsSecurity"]]
w("            " + "\n            | ".join(f"Setting::{camel(n)}" for n in true_names) + " => true,")
w("            " + "\n            | ".join(f"Setting::{camel(n)}" for n in false_names) + " => false,")
w("        }")
w("    }")
w("}")
(crate / "src/catalog.rs").write_text("\n".join(out) + "\n", encoding="utf-8")
print(f"src/catalog.rs: {len(catalog)} settings")
