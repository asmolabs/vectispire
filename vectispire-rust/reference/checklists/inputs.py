"""Writes reference/checklists/inputs.json, the cases the checklists vocabulary is held to: python3 inputs.py inputs.json."""
import json
import sys

out = {}

# ChecklistText.normalize: NFKC, whitespace and controls as one space, format characters removed, trimmed.
out["texts"] = [
    None, "", "   ", "Plain", "  two  spaces  ", "line\nbreak\r\ninside", "tab\tand\u000bvt",
    "non breaking", "zero​width", "soft­hyphen", "﻿bom", "ligature ﬁle",
    "full１widthａ", " line para", "é composed", "Ǆ dz", "　ideographic",
    "\u0085next line", "\u001fcontrol\u007f", "‍‌ joiners", "Ⅻ roman", "㎒ unit", "Cap Kept",
    "\U0001d400 math bold", "emoji \U0001f600 kept", "᠎ mongolian", "⁠word joiner",
    "퟿", "ﬀ ﬃ ﬄ", "x\u0000nul", "µ micro", "K kelvin",
]

# ItemKey.fromId / fromControl.
out["itemIds"] = [None, "", "  ", "A.1", "  a.1  ", "ID with space", "x" * 200, "x" * 201, "Ａ-1",
                  "\U0001f600" * 100, "\U0001f600" * 101]
out["controls"] = [None, "", " ", "Encrypt data at rest", "ENCRYPT  data\nat rest", "Ǆ", "İstanbul", "ß straße",
                   "Ⅷ is eight"]

out["answers"] = [None, "", "  ", "yes", " YES ", "No", "not_applicable", "Not_Applicable", "n/a", "maybe",
                  "x" * 60, "yıes"]
out["authors"] = [None, "person", "system", "SYSTEM", "robot", ""]

out["answerWords"] = [
    {"yes": "Oui", "no": "Non", "notApplicable": None, "words": ["oui", " OUI ", "Non", "NA", None, "Ou i"]},
    {"yes": "Oui", "no": "Non", "notApplicable": "Sans objet",
     "words": ["sans  objet", "SANS OBJET", "Oui", "oui "]},
    {"yes": "Yes", "no": "yes", "notApplicable": None, "words": []},
    {"yes": "Yes", "no": "No", "notApplicable": " no ", "words": []},
    {"yes": " ", "no": "No", "notApplicable": None, "words": []},
    {"yes": "Yes", "no": "x" * 256, "notApplicable": None, "words": []},
    {"yes": "Yes", "no": "No", "notApplicable": "", "words": []},
    {"yes": "ﬁ", "no": "FI", "notApplicable": None, "words": []},
    {"yes": "Ja", "no": "Nee", "notApplicable": "N.v.t.", "words": ["n.v.t.", "ja", "JA", "nee "]},
]
out["givenAnswers"] = [
    {"value": "yes", "comment": None, "offersNotApplicable": False},
    {"value": "yes", "comment": "  ", "offersNotApplicable": False},
    {"value": "no", "comment": None, "offersNotApplicable": True},
    {"value": "no", "comment": "  ", "offersNotApplicable": True},
    {"value": "no", "comment": " because ", "offersNotApplicable": True},
    {"value": "not_applicable", "comment": "out of scope", "offersNotApplicable": False},
    {"value": "not_applicable", "comment": None, "offersNotApplicable": True},
    {"value": "not_applicable", "comment": "out of scope", "offersNotApplicable": True},
    {"value": "no", "comment": "x" * 4000, "offersNotApplicable": False},
    {"value": "no", "comment": "x" * 4001, "offersNotApplicable": False},
    {"value": "no", "comment": "\U0001f600" * 2000, "offersNotApplicable": False},
    {"value": "no", "comment": "\U0001f600" * 2001, "offersNotApplicable": False},
]

out["evidence"] = [
    {"kind": "none", "validity": None}, {"kind": "NONE", "validity": 3}, {"kind": "file", "validity": None},
    {"kind": " link_or_file ", "validity": 12}, {"kind": "file", "validity": 0}, {"kind": "file", "validity": 120},
    {"kind": "file", "validity": 121}, {"kind": "", "validity": None}, {"kind": None, "validity": None},
    {"kind": "pdf", "validity": None}, {"kind": "x" * 50, "validity": None},
]

item = {"key": {"control": "Encrypt data at rest"}, "position": 1, "row": 7, "domain": "Data",
        "objective": "Confidentiality", "control": "Encrypt data at rest", "contact": "PO",
        "kpi": "All stores", "evidence": {"kind": "none", "validity": None}, "boundRule": None}


def variant(**changes):
    copy = json.loads(json.dumps(item))
    copy.update(changes)
    return copy


out["items"] = [
    item,
    variant(contact="Arch / BA", position=3, row=12),
    variant(control="Encrypt  data\nat rest"),
    variant(control="encrypt data at rest"),
    variant(kpi=None, domain=None, objective="  "),
    variant(evidence={"kind": "file", "validity": 6}),
    variant(boundRule='{"kind":"dependency_analysis","maxAgeDays":7,"requireSchedule":true}'),
    variant(control="   "),
    variant(control="x" * 4001),
    variant(control="x" * 4000),
    variant(contact="c" * 256),
    variant(domain="d" * 1001),
    variant(kpi="\U0001f600" * 2001),
    variant(position=0),
    variant(row=0),
    variant(key={"id": "A.1"}),
    variant(domain="ﬁ", objective=" x"),
]


def it(key, control, row, position=1, kpi="k", evidence=None, rule=None):
    return {"key": key, "position": position, "row": row, "domain": "D", "objective": "O", "control": control,
            "contact": "", "kpi": kpi, "evidence": evidence or {"kind": "none", "validity": None},
            "boundRule": rule}


a = it({"control": "Alpha"}, "Alpha", 2)
b = it({"control": "Beta"}, "Beta", 3, 2)
c = it({"control": "Gamma"}, "Gamma", 4, 3)
b2 = it({"control": "Beta"}, "Beta", 5, 2, kpi="changed")
d = it({"control": "Delta"}, "Delta", 6, 4)
g2 = it({"control": "Gamma reworded"}, "Gamma reworded", 7, 3)
out["pairings"] = [
    {"previous": [a, b, c], "next": [a, b2, d, g2], "byHand": []},
    {"previous": [a, b, c], "next": [a, b2, d, g2], "byHand": [[{"control": "Gamma reworded"}, {"control": "Gamma"}]]},
    {"previous": [a, b, c], "next": [a, g2], "byHand": [[{"control": "Gamma reworded"}, {"control": "Beta"}],
                                                       [{"control": "Gamma reworded"}, {"control": "Gamma"}]]},
    {"previous": [a, b, c], "next": [a, d, g2], "byHand": [[{"control": "Gamma reworded"}, {"control": "Gamma"}],
                                                          [{"control": "Delta"}, {"control": "Gamma"}]]},
    {"previous": [a, b], "next": [a, d], "byHand": [[{"control": "Alpha"}, {"control": "Beta"}]]},
    {"previous": [a, b], "next": [a, d], "byHand": [[{"control": "Delta"}, {"control": "Alpha"}]]},
    {"previous": [a, b], "next": [a, d], "byHand": [[{"control": "Nowhere"}, {"control": "Beta"}]]},
    {"previous": [a, b], "next": [a, d], "byHand": [[{"control": "Delta"}, {"control": "Nowhere"}]]},
    {"previous": [], "next": [a], "byHand": []},
    {"previous": [a, b], "next": [], "byHand": []},
]

out["contacts"] = [None, "", "PO", "PO / BA", " Arch / ARCH /arch ", "AUTO", "auto / PO", "PO//BA", "/", "ß",
                   "Ǆ / ǅ", "PO  / ﬁ"]
out["contactKeys"] = [None, "", "arch", " A r ", "PO/BA", "ﬁ", "straße", "  ", "auto"]

lines = [{"position": 1, "control": "Short control"},
         {"position": 2, "control": "Multi\nline   control"},
         {"position": 3, "control": "x" * 159},
         {"position": 4, "control": "y" * 160},
         {"position": 5, "control": "z" * 161},
         {"position": 6, "control": ("w" * 158) + "  tail of a long control"}]
many = [{"position": n, "control": "Line %d" % n} for n in range(1, 24)]
out["reminders"] = {
    "toContact": [
        {"name": "Alice", "profiles": [{"projectId": 4, "projectName": "Ledger", "profile": "PO", "lines": lines}],
         "week": "2026-10-26", "publicUrl": "https://vectispire.example.org///"},
        {"name": None, "profiles": [{"projectId": 4, "projectName": "Ledger", "profile": "PO", "lines": lines[:1]}],
         "week": "2026-10-26", "publicUrl": None},
        {"name": "Bob", "profiles": [{"projectId": 4, "projectName": "Ledger", "profile": "PO", "lines": many},
                                     {"projectId": 9, "projectName": "Payroll", "profile": "Arch", "lines": many[:20]}],
         "week": "2027-01-04", "publicUrl": "https://v.example.org"},
    ],
    "toCiso": [
        {"unreached": [{"projectId": 4, "projectName": "Ledger", "profile": "PO", "lines": 1, "gap": "NOBODY_LINKED"}],
         "week": "2026-10-26", "publicUrl": None},
        {"unreached": [{"projectId": 4, "projectName": "Ledger", "profile": "PO", "lines": 3, "gap": "ACCOUNT_GONE"},
                       {"projectId": 5, "projectName": "B", "profile": "BA", "lines": 1, "gap": "ACCOUNT_INACTIVE"},
                       {"projectId": 6, "projectName": "C", "profile": "QA", "lines": 2, "gap": "NO_EMAIL"},
                       {"projectId": 7, "projectName": "D", "profile": "SEC", "lines": 9, "gap": "CANNOT_FILL"}],
         "week": "2026-12-28", "publicUrl": "http://x/"},
    ],
}

out["scopes"] = [None, "", "  ", "builtin:secret", " builtin:sast ", "builtin:SAST", "builtin:plugin", "builtin:ai_review",
                 "builtin:", "plugin:java-arch", "plugin:Bad_Id", "plugin:-x", "plugin:x", "plugin:" + "a" * 64,
                 "plugin:" + "a" * 65, "import:ledger-ci/ESLint", "import:ledger-ci/ ESLint ", "import:ledger-ci",
                 "import:l/eslint", "import:ledger-ci/", "import:ledger-ci/a,b", "import:-x/t", "import:x" * 1 + "y/t",
                 "import:ledger-ci/" + "t" * 100, "import:ledger-ci/" + "t" * 101, "import:LEDGER/t", "sast",
                 "plugin:" + "x" * 300, "import:ledger-ci/tool\u0085x"]

out["coverageScopes"] = [
    {"include": ["**/service/**"], "exclude": None,
     "paths": ["", "service", "org/example/service", "org/example/service/impl", "org/example/services", "Service"]},
    {"include": None, "exclude": ["org/example/*-api", "**/generated/**"],
     "paths": ["org/example/ledger-api", "org/example/api", "org/example/x/ledger-api", "gen/generated", "a/b"]},
    {"include": ["org/example", "org/example/**"], "exclude": ["org/example/test/**"],
     "paths": ["org/example", "org/example/a", "org/example/test", "org/example/test/b", "org"]},
    {"include": ["*"], "exclude": None, "paths": ["", "a", "a/b"]},
    {"include": ["**"], "exclude": None, "paths": ["", "a", "a/b"]},
    {"include": ["a/**/b/**/c"], "exclude": None, "paths": ["a/b/c", "a/x/b/y/z/c", "a/c", "a/b/b/c"]},
    {"include": ["*a*b*"], "exclude": None, "paths": ["ab", "xaxbx", "ba", "aab", "a/b"]},
    {"include": [], "exclude": []},
    {"include": None, "exclude": None},
    {"include": ["org.example.service"], "exclude": None},
    {"include": ["a?b"], "exclude": None},
    {"include": ["a[b]"], "exclude": None},
    {"include": ["a{b}"], "exclude": None},
    {"include": ["!a"], "exclude": None},
    {"include": ["a\\b"], "exclude": None},
    {"include": ["/a"], "exclude": None},
    {"include": ["a/"], "exclude": None},
    {"include": ["a//b"], "exclude": None},
    {"include": ["a/./b"], "exclude": None},
    {"include": ["a/../b"], "exclude": None},
    {"include": ["a/x**/b"], "exclude": None},
    {"include": ["  "], "exclude": None},
    {"include": ["b", "a", "b"], "exclude": None},
    {"include": ["x" * 501], "exclude": None},
    {"include": ["p%d" % n for n in range(21)], "exclude": None},
    {"include": ["z", " a ", "m"], "exclude": ["q"], "paths": ["a", "z", "q"]},
    {"include": ["a\u0001b"], "exclude": None},
    {"include": ["v1.2/x"], "exclude": None, "paths": ["v1.2/x"]},
]

out["suites"] = [
    {"pattern": "*Test", "names": ["FooTest", "Test", "FooTests", "foo.BarTest", None, ""]},
    {"pattern": "com.example.arch.*", "names": ["com.example.arch.LayersTest", "com.example.archi.X",
                                                "com.example.arch."]},
    {"pattern": "?", "names": ["a", "", "ab", "\U0001f600"]},
    {"pattern": "??", "names": ["\U0001f600", "ab"]},
    {"pattern": "*a*b*c", "names": ["abc", "aXbYc", "acb", "aabbcc", "abcc"]},
    {"pattern": "**", "names": ["", "x"]},
    {"pattern": "a?c*", "names": ["abc", "ac", "abcdef", "aéc"]},
]

# A star is a star before it is a character: "*a" matches "*xa".
out["suites"].append({"pattern": "*a", "names": ["*xa", "xa", "*a", "a"]})

qualifiers = ["1-alpha2snapshot", "1-alpha2", "1-alpha-123", "1-beta-2", "1-beta123", "1-m2", "1-m11", "1-rc",
              "1-cr2", "1-rc123", "1-SNAPSHOT", "1", "1-sp", "1-sp2", "1-sp123", "1-abc", "1-def", "1-pom-1",
              "1-1-snapshot", "1-1", "1-2", "1-123"]
numbers = ["2.0", "2.0.a", "2-1", "2.0.2", "2.0.123", "2.1.0", "2.1-a", "2.1b", "2.1-c", "2.1-1", "2.1.0.1", "2.2",
           "2.123", "11.a2", "11.a11", "11.b2", "11.b11", "11.m2", "11.m11", "11", "11.a", "11b", "11c", "11m"]
equal = ["1", "1.0", "1.0.0", "1-0", "1.0-0", "1.ga", "1-ga", "1.final", "1-final", "1.release", "1-release",
         "1.0.0.RELEASE", "1a1", "1-a1", "1-alpha-1", "1alpha1", "2.0.a", "2.0.0.a", "2-a", "1.0.0.M1", "1-m1",
         "1-milestone-1", "1rc", "1cr", "1.RC", "1-SNAPSHOT", "1.0-SNAPSHOT", "12345678901234567890",
         "12345678901234567890.0"]
odd = ["", " ", ".", "-", "1..1", "1--1", "1.-1", "-1", ".1", "1.", "1-", "１.０", "1.٣", "İ",
       "1.0.0-alpha", "1.17.0-RC1", "1.17.0-SNAPSHOT", "1.17.0", "1.17.0.RELEASE-sp", "5.3.0.RELEASE", "1-0.1",
       "1-0-alpha", "1.9", "1.10", "1.0.0.X1", "1.0.0-X2", "a", "b1", "m", "abc1", "1.0a", "1.0.a1",
       "99999999999999999999999.1", "1.2.3.4.5.6.7.8.9", "1-\U0001d7cf", "é", "1.ga.0", "0", "0.0", "sp"]
versions = []
pool = qualifiers + numbers + equal + odd
for i, left in enumerate(pool):
    for right in pool[i:]:
        versions.append([left, right])
out["versions"] = versions

out["ranges"] = [
    {"spec": s, "versions": ["0.9", "1.0", "1.1", "1.2", "1.5", "1.17", "1.17.7", "1.99", "2.0-SNAPSHOT", "2.0",
                              "2.0.1", "3.0", "5.3.0", "1.0-alpha"]}
    for s in ["(,)", "(,2.0)", "(,5.3.0)", "(1.0)", "(1.0,1.0)", "(1.17,2.0]", "[,2.0)", "[1 .0,2]", "[1.0,1.0)",
              "[1.0,1.1)", "[1.0,1.2] 1.4", "[1.0,1.2], [1.5,)", "[1.0,1.2],", "[1.0,1.2],(,3.0)",
              "[1.0,1.5),[1.5,2.0]", "[1.0,1.5],[1.2,2.0]", "[1.0,1.5],[1.5,2.0]", "[1.0,2.0", "[1.0,2.0,3.0]",
              "[1.0,]", "[1.17,2.0)", "[1.17.7]", "[1.5,)", "[1.5,2.0],[1.0,1.2]", "[2.0,1.0]", "[3.2",
              "[3.2,4)", "[5.3.0]", "[]", "1.0", "", None, " [1.0,2.0) ", "[1.0,1.0]", "(1.0,2.0)",
              "[1.0 ,2.0]", "[1.0\u0001,2.0]", "[x" + "y" * 80 + "]", "(,1.0],[1.2,1.3)", "[1.0)", "(1.0]",
              "[1.0,2.0)(2.0,3.0)", "[1.0,2.0) ,  [3.0,4.0)", "[1.0,1.0],[1.0,2.0]", "[1.0,1.0),[1.0,2.0]",
              "[1-SNAPSHOT,1]", "[1.0.RELEASE,1]"]
]

# Rules: as a request states them (parse) — each refused in words, or its canonical form and digest.
rules = [
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["import:quality-server/SonarQube","builtin:sast"],'
    '"thresholds":{"medium":{"minResolvedRatio":0.60},"critical":{"maxOpen":0},"high":{"maxOpen":2}}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret"],'
    '"thresholds":{"critical":{"maxOpen":0},"high":{"maxOpen":0}}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret","builtin:secret"],"thresholds":{"high":{"maxOpen":0}}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":[],"thresholds":{"high":{"maxOpen":0}}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret"],"thresholds":{}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret"]}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":"builtin:secret","thresholds":{"high":{"maxOpen":0}}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":[1],"thresholds":{"high":{"maxOpen":0}}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret"],"thresholds":{"severe":{"maxOpen":0}}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret"],"thresholds":{"high":{}}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret"],"thresholds":{"high":3}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret"],"thresholds":[]}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret"],"thresholds":{"high":{"maxOpen":0,"other":1}}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret"],"thresholds":{"high":{"maxOpen":0,"other":null}}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret"],"thresholds":{"high":{"maxOpen":-1}}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret"],"thresholds":{"high":{"maxOpen":1000001}}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret"],"thresholds":{"high":{"maxOpen":1000000}}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret"],"thresholds":{"high":{"maxOpen":1.5}}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret"],"thresholds":{"high":{"maxOpen":"1"}}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret"],"thresholds":{"high":{"minResolvedRatio":1.0}}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret"],"thresholds":{"high":{"minResolvedRatio":0}}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret"],"thresholds":{"high":{"minResolvedRatio":0.00010}}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret"],"thresholds":{"high":{"minResolvedRatio":0.00001}}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret"],"thresholds":{"high":{"minResolvedRatio":1.01}}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret"],"thresholds":{"high":{"minResolvedRatio":-0.1}}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret"],"thresholds":{"high":{"minResolvedRatio":6E-1}}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret"],"thresholds":{"high":{"minResolvedRatio":"0.5"}}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret"],"thresholds":{"HIGH":{"maxOpen":1},"high":{"maxOpen":2}}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret"],"thresholds":{"unknown":{"maxOpen":1},"negligible":{"maxOpen":2},"low":{"minResolvedRatio":0.5}}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["plugin:b","import:a-a/t","builtin:iac","builtin:eol","builtin:license","builtin:quality","builtin:vulnerability"],"thresholds":{"high":{"maxOpen":0}}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["s1","s2"],"thresholds":{"high":{"maxOpen":0}}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":[' + ",".join('"plugin:p%02d"' % n for n in range(21)) + '],"thresholds":{"high":{"maxOpen":0}}}',
    '{"kind":"findings_threshold","maxAgeDays":7,"scopes":[' + ",".join('"plugin:p%02d"' % n for n in range(20)) + '],"thresholds":{"high":{"maxOpen":0}}}',
    '{"kind":"dependency_analysis","maxAgeDays":7}',
    '{"kind":"dependency_analysis","maxAgeDays":7,"requireSchedule":true}',
    '{"kind":"dependency_analysis","maxAgeDays":7,"requireSchedule":false,"thresholds":{"critical":{"maxOpen":0}}}',
    '{"kind":"dependency_analysis","maxAgeDays":7,"requireSchedule":"yes"}',
    '{"kind":"dependency_analysis","maxAgeDays":7,"requireSchedule":true,"scopes":["builtin:sast"]}',
    '{"kind":"dependency_analysis","maxAgeDays":7,"requireSchedule":true,"scopes":null}',
    '{"kind":"dependency_analysis","maxAgeDays":0,"requireSchedule":true}',
    '{"kind":"dependency_analysis","maxAgeDays":366,"requireSchedule":true}',
    '{"kind":"dependency_analysis","maxAgeDays":367,"requireSchedule":true}',
    '{"kind":"dependency_analysis","maxAgeDays":7.0,"requireSchedule":true}',
    '{"kind":"dependency_analysis","maxAgeDays":"7","requireSchedule":true}',
    '{"kind":"dependency_analysis","maxAgeDays":4294967303,"requireSchedule":true}',
    '{"kind":"dependency_analysis","requireSchedule":true}',
    '{"kind":"Dependency_Analysis ","maxAgeDays":7,"requireSchedule":true}',
    '{"kind":"sbom","maxAgeDays":7}',
    '{"kind":"' + "k" * 60 + '","maxAgeDays":7}',
    '{"maxAgeDays":7}',
    '{"kind":7,"maxAgeDays":7}',
    '[]', '"rule"', 'null', '', '{', '{"kind":"dependency_analysis","maxAgeDays":7,"requireSchedule":true} trailing',
    '{"kind":"coverage_threshold","maxAgeDays":30,"metric":"line","minimumRatio":0.8,"aggregation":"per_repository"}',
    '{"kind":"coverage_threshold","maxAgeDays":30,"metric":"BRANCH","minimumRatio":1,"aggregation":"project_weighted"}',
    '{"kind":"coverage_threshold","maxAgeDays":30,"metric":"line","minimumRatio":0,"aggregation":"per_repository"}',
    '{"kind":"coverage_threshold","maxAgeDays":30,"metric":"line","minimumRatio":0.80000,"aggregation":"per_repository"}',
    '{"kind":"coverage_threshold","maxAgeDays":30,"metric":"lines","minimumRatio":0.8,"aggregation":"per_repository"}',
    '{"kind":"coverage_threshold","maxAgeDays":30,"minimumRatio":0.8,"aggregation":"per_repository"}',
    '{"kind":"coverage_threshold","maxAgeDays":30,"metric":"line","aggregation":"per_repository"}',
    '{"kind":"coverage_threshold","maxAgeDays":30,"metric":"line","minimumRatio":0.8}',
    '{"kind":"coverage_threshold","maxAgeDays":30,"metric":"line","minimumRatio":0.8,"aggregation":"per_repository",'
    '"scope":{"include":["**/service/**"],"exclude":["**/generated/**"]}}',
    '{"kind":"coverage_threshold","maxAgeDays":30,"metric":"line","minimumRatio":0.8,"aggregation":"per_repository","scope":{"exclude":["z","a"]}}',
    '{"kind":"coverage_threshold","maxAgeDays":30,"metric":"line","minimumRatio":0.8,"aggregation":"per_repository","scope":{}}',
    '{"kind":"coverage_threshold","maxAgeDays":30,"metric":"line","minimumRatio":0.8,"aggregation":"per_repository","scope":null}',
    '{"kind":"coverage_threshold","maxAgeDays":30,"metric":"line","minimumRatio":0.8,"aggregation":"per_repository","scope":[]}',
    '{"kind":"coverage_threshold","maxAgeDays":30,"metric":"line","minimumRatio":0.8,"aggregation":"per_repository","scope":{"include":"a"}}',
    '{"kind":"coverage_threshold","maxAgeDays":30,"metric":"line","minimumRatio":0.8,"aggregation":"per_repository","scope":{"include":[1]}}',
    '{"kind":"coverage_threshold","maxAgeDays":30,"metric":"line","minimumRatio":0.8,"aggregation":"per_repository","scope":{"other":["a"]}}',
    '{"kind":"coverage_threshold","maxAgeDays":30,"metric":"line","minimumRatio":0.8,"aggregation":"per_repository","scope":{"include":["a"],"other":null}}',
    '{"kind":"test_suite_passed","maxAgeDays":7,"minimumTests":1,"suitePattern":"*Test"}',
    '{"kind":"test_suite_passed","maxAgeDays":7,"minimumTests":1}',
    '{"kind":"test_suite_passed","maxAgeDays":7,"minimumTests":1,"suitePatterns":["*IT","*Test","*IT"]}',
    '{"kind":"test_suite_passed","maxAgeDays":7,"minimumTests":1,"suitePatterns":["*IT"]}',
    '{"kind":"test_suite_passed","maxAgeDays":7,"minimumTests":1,"suitePattern":"*Test","suitePatterns":["*IT"]}',
    '{"kind":"test_suite_passed","maxAgeDays":7,"minimumTests":1,"suitePattern":"*Test","suitePatterns":null}',
    '{"kind":"test_suite_passed","maxAgeDays":7,"minimumTests":1,"suitePatterns":[]}',
    '{"kind":"test_suite_passed","maxAgeDays":7,"minimumTests":1,"suitePatterns":"*IT"}',
    '{"kind":"test_suite_passed","maxAgeDays":7,"minimumTests":1,"suitePatterns":[1]}',
    '{"kind":"test_suite_passed","maxAgeDays":7,"minimumTests":1,"suitePatterns":[' + ",".join('"p%d"' % n for n in range(11)) + ']}',
    '{"kind":"test_suite_passed","maxAgeDays":7,"minimumTests":0,"suitePattern":"*Test"}',
    '{"kind":"test_suite_passed","maxAgeDays":7,"minimumTests":10000001,"suitePattern":"*Test"}',
    '{"kind":"test_suite_passed","maxAgeDays":7,"minimumTests":1,"suitePattern":"  "}',
    '{"kind":"test_suite_passed","maxAgeDays":7,"minimumTests":1,"suitePattern":" a\\tb "}',
    '{"kind":"test_suite_passed","maxAgeDays":7,"minimumTests":1,"suitePattern":"' + "p" * 501 + '"}',
    '{"kind":"test_suite_passed","maxAgeDays":7,"suitePattern":"*Test"}',
    '{"kind":"component_versions","maxAgeDays":30,"components":[{"purlPrefix":"pkg:maven/com.example/ledger-core","versions":["3.2.1","3.1.0","3.2.1"]}]}',
    '{"kind":"component_versions","maxAgeDays":7,"components":[{"purlPrefix":"pkg:maven/org.example.platform","versions":["[1.17,2.0)","1.16.4","(,1.0],[1.2,1.3)"]}]}',
    '{"kind":"component_versions","maxAgeDays":7,"components":[{"purlPrefix":"pkg:maven/org.example.platform","versions":["[2.0,1.17)"]}]}',
    '{"kind":"component_versions","maxAgeDays":7,"components":[{"purlPrefix":"pkg:maven/org.example.platform","versions":["[1.17,2.0"]}]}',
    '{"kind":"component_versions","maxAgeDays":7,"components":[{"purlPrefix":"pkg:npm/left-pad","versions":["[1.0,2.0)"]}]}',
    '{"kind":"component_versions","maxAgeDays":7,"components":[{"purlPrefix":"pkg:npm/left-pad","versions":["1.0"," 1.0 "]}]}',
    '{"kind":"component_versions","maxAgeDays":30,"components":[{"purlPrefix":"pkg:maven/com.example.tools/","versions":["1.0.0"]}]}',
    '{"kind":"component_versions","maxAgeDays":30,"components":[{"purlPrefix":"pkg:maven/b","versions":["1"]},{"purlPrefix":"pkg:maven/a","versions":["2"]}]}',
    '{"kind":"component_versions","maxAgeDays":30,"components":[{"purlPrefix":"pkg:maven/a","versions":["1"]},{"purlPrefix":" pkg:maven/a","versions":["2"]}]}',
    '{"kind":"component_versions","maxAgeDays":30,"components":[{"purlPrefix":"pkg:maven/a","versions":[]}]}',
    '{"kind":"component_versions","maxAgeDays":30,"components":[{"purlPrefix":"pkg:maven/a","versions":[" "]}]}',
    '{"kind":"component_versions","maxAgeDays":30,"components":[{"purlPrefix":"pkg:maven/a","versions":[1]}]}',
    '{"kind":"component_versions","maxAgeDays":30,"components":[{"purlPrefix":"pkg:maven/a"}]}',
    '{"kind":"component_versions","maxAgeDays":30,"components":[{"versions":["1"]}]}',
    '{"kind":"component_versions","maxAgeDays":30,"components":[{"purlPrefix":"maven/a","versions":["1"]}]}',
    '{"kind":"component_versions","maxAgeDays":30,"components":[{"purlPrefix":"pkg:","versions":["1"]}]}',
    '{"kind":"component_versions","maxAgeDays":30,"components":[{"purlPrefix":"pkg:maven/a b","versions":["1"]}]}',
    '{"kind":"component_versions","maxAgeDays":30,"components":["pkg:maven/a"]}',
    '{"kind":"component_versions","maxAgeDays":30,"components":{}}',
    '{"kind":"component_versions","maxAgeDays":30,"components":[]}',
    '{"kind":"component_versions","maxAgeDays":30,"components":[{"purlPrefix":"pkg:maven/a","versions":["\\u00e9","Z","a","\\ud83d\\ude00","\\uffff"]}]}',
    '{"kind":"component_versions","maxAgeDays":30,"components":[{"purlPrefix":"pkg:maven/a","versions":["' + "v" * 256 + '"]}]}',
    '{"kind":"component_versions","maxAgeDays":30,"components":[{"purlPrefix":"pkg:maven/\\uffff","versions":["1"]},{"purlPrefix":"pkg:maven/\\ud83d\\ude00","versions":["1"]}]}',

    '{"kind":"component_present","maxAgeDays":30,"components":[{"purlPrefix":"pkg:maven/org.example.platform/platform-application"},{"purlPrefix":" pkg:maven/org.example.platform "}]}',
    '{"kind":"component_present","maxAgeDays":30,"components":[{"purlPrefix":"pkg:maven/org.example.platform","versions":["1.0"]}]}',
    '{"kind":"component_present","maxAgeDays":30,"components":[{"purlPrefix":"pkg:maven/org.example/"}]}',
    '{"kind":"component_present","maxAgeDays":30,"components":[{"purlPrefix":"pkg:maven/org.example"},{"purlPrefix":"pkg:maven/org.example "}]}',
    '{"kind":"component_present","maxAgeDays":30,"components":[]}',
    '{"kind":"component_present","maxAgeDays":30,"components":[{"purlPrefix":"pkg:maven/a","pinned":true}]}',
    '{"kind":"component_present","maxAgeDays":30,"components":[{"purlPrefix":"pkg:maven/a","pinned":null,"versions":null}]}',
    '{"kind":"component_present","maxAgeDays":30,"components":[{"purlPrefix":"pkg:maven/a@1.0"}]}',
    '{"kind":"component_present","maxAgeDays":30,"components":[{"purlPrefix":"pkg:maven/a#x"}]}',
    '{"kind":"component_present","maxAgeDays":30,"components":[{"purlPrefix":"pkg:maven/a?"}]}',
    '{"kind":"change_review","maxAgeDays":2,"minimumApprovals":1,"windowDays":30,"minimumRatio":1}',
    '{"kind":"change_review","maxAgeDays":2,"minimumApprovals":2,"windowDays":30,"minimumRatio":0.9,"branch":" release/2026 "}',
    '{"kind":"change_review","maxAgeDays":2,"minimumApprovals":0,"windowDays":30,"minimumRatio":1}',
    '{"kind":"change_review","maxAgeDays":2,"minimumApprovals":11,"windowDays":30,"minimumRatio":1}',
    '{"kind":"change_review","maxAgeDays":2,"minimumApprovals":1,"windowDays":0,"minimumRatio":1}',
    '{"kind":"change_review","maxAgeDays":2,"minimumApprovals":1,"windowDays":367,"minimumRatio":1}',
    '{"kind":"change_review","maxAgeDays":2,"minimumApprovals":1,"windowDays":30,"minimumRatio":0}',
    '{"kind":"change_review","maxAgeDays":2,"minimumApprovals":1,"windowDays":30}',
    '{"kind":"change_review","maxAgeDays":2,"windowDays":30,"minimumRatio":1}',
    '{"kind":"change_review","maxAgeDays":2,"minimumApprovals":1,"minimumRatio":1}',
    '{"kind":"change_review","maxAgeDays":2,"minimumApprovals":1,"windowDays":30,"minimumRatio":1,"branch":"a..b"}',
    '{"kind":"change_review","maxAgeDays":2,"minimumApprovals":1,"windowDays":30,"minimumRatio":1,"branch":"a b"}',
    '{"kind":"change_review","maxAgeDays":2,"minimumApprovals":1,"windowDays":30,"minimumRatio":1,"branch":"a~1"}',
    '{"kind":"change_review","maxAgeDays":2,"minimumApprovals":1,"windowDays":30,"minimumRatio":1,"branch":"  "}',
    '{"kind":"change_review","maxAgeDays":2,"minimumApprovals":1,"windowDays":30,"minimumRatio":1,"branch":"' + "b" * 256 + '"}',
    '{"kind":"change_review","maxAgeDays":2,"minimumApprovals":1,"windowDays":30,"minimumRatio":1,"branch":"r\\u2003x"}',
    '{"kind":"change_review","maxAgeDays":2,"minimumApprovals":1,"windowDays":30,"minimumRatio":1,"branch":"r\\u00a0x"}',
    '{"kind":"change_review","maxAgeDays":2,"minimumApprovals":1,"windowDays":30,"minimumRatio":1,"branch":7}',
]
out["rules"] = rules

# Stored canonical forms read back: a check added after a rule was bound must not refuse it.
out["storedRules"] = [
    '{"components":[{"purlPrefix":"pkg:npm/left-pad","versions":["[1.0,2.0)"]}],"kind":"component_versions","maxAgeDays":7}',
    '{"components":[{"purlPrefix":"pkg:maven/org.example/"}],"kind":"component_present","maxAgeDays":30}',
    '{"components":[{"purlPrefix":"pkg:maven/org.example/","versions":["1"]}],"kind":"component_versions","maxAgeDays":30}',
    '{"kind":"dependency_analysis","maxAgeDays":7,"requireSchedule":true}',
    '{"kind":"coverage_threshold","maxAgeDays":30,"metric":"line","minimumRatio":0.8,"aggregation":"per_repository"}',
    'not json',
]


# ------------------------------------------------------------------ evaluations
NOW = "2026-09-29T12:00:00Z"
FRESH = "2026-09-28T12:00:00Z"
FRESH_EARLIER = "2026-09-28T11:59:00.123456789Z"
OLDER = "2026-09-28T07:00:00Z"
OLD = "2026-08-30T12:00:00Z"
EDGE = "2026-09-22T12:00:00Z"  # exactly seven days before NOW: within the age


def look(at, source="scan", ident=1, digest=None):
    return [source, ident, at, digest]


def scanned(newest, sbom=True, recorded=1, unrecorded=0):
    return {"scanned": {"newest": newest, "sbom": sbom, "recorded": recorded, "unrecorded": unrecorded}}


def runs(entries, scans=1, before=False):
    return {"plugin": {"runs": [{"scan": e[0], "state": e[1], "reads": e[2] if len(e) > 2 else None}
                                for e in entries], "scans": scans, "namedBefore": before}}


def facts(repos, **parts):
    base = {"repositories": repos}
    base.update(parts)
    return base


SECRETS = ('{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret"],'
           '"thresholds":{"critical":{"maxOpen":0},"high":{"maxOpen":0}}}')
PLUGIN = ('{"kind":"findings_threshold","maxAgeDays":7,"scopes":["plugin:java-arch"],'
          '"thresholds":{"high":{"maxOpen":0}}}')
SAST = ('{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:sast"],'
        '"thresholds":{"medium":{"minResolvedRatio":0.6}}}')
IMPORTS = ('{"kind":"findings_threshold","maxAgeDays":7,"scopes":["import:ledger-ci/eslint"],'
           '"thresholds":{"high":{"maxOpen":0}}}')
MIXED = ('{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret","builtin:iac"],'
         '"thresholds":{"high":{"maxOpen":1,"minResolvedRatio":0.5},"low":{"maxOpen":3}}}')
DEPS = '{"kind":"dependency_analysis","maxAgeDays":7,"requireSchedule":true}'
DEPS_T = ('{"kind":"dependency_analysis","maxAgeDays":1,"requireSchedule":true,'
          '"thresholds":{"critical":{"maxOpen":0}}}')
LINES = '{"kind":"coverage_threshold","maxAgeDays":7,"metric":"line","minimumRatio":0.8,"aggregation":"per_repository"}'
WEIGHTED = '{"kind":"coverage_threshold","maxAgeDays":7,"metric":"line","minimumRatio":0.8,"aggregation":"project_weighted"}'
BRANCHES = '{"kind":"coverage_threshold","maxAgeDays":7,"metric":"branch","minimumRatio":0.5,"aggregation":"per_repository"}'
SCOPED = ('{"kind":"coverage_threshold","maxAgeDays":7,"metric":"line","minimumRatio":0.75,"aggregation":"per_repository",'
          '"scope":{"include":["**/service/**"],"exclude":["**/generated/**"]}}')
SCOPED_BRANCH = ('{"kind":"coverage_threshold","maxAgeDays":7,"metric":"branch","minimumRatio":0.5,'
                 '"aggregation":"project_weighted","scope":{"include":["org/**"]}}')
TESTS = '{"kind":"test_suite_passed","maxAgeDays":7,"suitePattern":"com.example.arch.*","minimumTests":3}'
TESTS2 = '{"kind":"test_suite_passed","maxAgeDays":7,"suitePatterns":["*Test","*IT"],"minimumTests":3}'
COMPONENTS = ('{"kind":"component_versions","maxAgeDays":7,"components":[{"purlPrefix":"pkg:maven/com.example/ledger-core",'
              '"versions":["3.2.1"]},{"purlPrefix":"pkg:maven/com.example/audit","versions":["1.0"]}]}')
RANGED = ('{"kind":"component_versions","maxAgeDays":7,"components":[{"purlPrefix":"pkg:maven/org.example.platform",'
          '"versions":["[1.17,2.0)","0.9.1"]}]}')
NPM_RANGE_STORED = '{"components":[{"purlPrefix":"pkg:npm/left","versions":["[1.0,2.0)","1.5"]}],"kind":"component_versions","maxAgeDays":7}'
SEPARATOR_STORED = '{"components":[{"purlPrefix":"pkg:maven/org.example/"}],"kind":"component_present","maxAgeDays":7}'
PRESENT = ('{"kind":"component_present","maxAgeDays":7,"components":[{"purlPrefix":"pkg:maven/org.example.platform"},'
           '{"purlPrefix":"pkg:npm/left"}]}')
REVIEW = '{"kind":"change_review","maxAgeDays":2,"minimumApprovals":1,"windowDays":30,"minimumRatio":1}'
REVIEW2 = ('{"kind":"change_review","maxAgeDays":2,"minimumApprovals":2,"windowDays":7,"minimumRatio":0.5,'
           '"branch":"release/2026"}')

vuln = "builtin:vulnerability"
ev = []


def case(name, rule, f, now=NOW, stored=False):
    ev.append({"name": name, "rule": rule, "stored": stored, "now": now, "facts": f})


case("no repository", SECRETS, facts([]))
case("never examined", SECRETS, facts([1]))
case("step absent", SECRETS, facts([1], scopes={"builtin:secret": {"1": scanned(look(OLD), True, 2, 0)}}))
case("unrecorded", SECRETS, facts([1], scopes={"builtin:secret": {"1": scanned(None, False, 0, 3)}}))
case("stale", SECRETS, facts([1], scopes={"builtin:secret": {"1": scanned(look(OLD), True, 0, 0)}}))
case("exactly at the age", SECRETS, facts([1], scopes={"builtin:secret": {"1": scanned(look(EDGE, ident=4))}}))
case("two reasons", SECRETS, facts([1, 2], scopes={"builtin:secret": {"1": scanned(look(OLD), True, 0, 0)}}))
case("one repository missing", SECRETS, facts([2, 1, 2], scopes={"builtin:secret": {"1": scanned(look(FRESH))}},
                                                 counts={"builtin:secret": {"1": [["critical", "open", 9]]}}))
case("clean pass", SECRETS, facts([1, 2], scopes={"builtin:secret": {
    "1": scanned(look(FRESH, ident=11)), "2": scanned(look(OLDER, ident=12))}}))
case("leaking fail", SECRETS, facts([1, 2], scopes={"builtin:secret": {
    "1": scanned(look(FRESH, ident=11)), "2": scanned(look(OLDER, ident=12))}},
    counts={"builtin:secret": {"2": [["high", "open", 1], ["high", "resolved", 3], ["medium", "open", 2]]}}))
case("a severity given twice", '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret"],'
     '"thresholds":{"HIGH":{"maxOpen":5},"high":{"maxOpen":0}}}',
     facts([1], scopes={"builtin:secret": {"1": scanned(look(FRESH))}}, counts={"builtin:secret": {"1": [["high", "open", 1]]}}))
case("unknown state stays open", SECRETS, facts([1], scopes={"builtin:secret": {"1": scanned(look(FRESH))}},
     counts={"builtin:secret": {"1": [["critical", "resolved", 4], ["critical", "quarantined", 1],
                                      ["weird", "open", 2]]}}))
case("mixed scopes", MIXED, facts([1, 2], scopes={
    "builtin:secret": {"1": scanned(look(FRESH, ident=1)), "2": scanned(look(FRESH, ident=2))},
    "builtin:iac": {"1": scanned(look(FRESH, ident=1)), "2": scanned(look(OLDER, ident=2))}},
    counts={"builtin:secret": {"1": [["high", "open", 1]], "2": [["high", "resolved", 1], ["low", "open", 2]]},
            "builtin:iac": {"1": [["high", "open", 1], ["low", "open", 2]], "3": [["high", "open", 50]]}}))
case("mixed scopes partial", MIXED, facts([1, 2], scopes={
    "builtin:secret": {"1": scanned(look(FRESH, ident=1)), "2": scanned(look(FRESH, ident=2))},
    "builtin:iac": {"1": scanned(look(FRESH, ident=1))}},
    counts={"builtin:secret": {"1": [["high", "open", 7]]}}))
for i, state in enumerate(["NOT_APPLICABLE", "ABSENT", "REFUSED_UNSIGNED", "REFUSED_SIGNATURE_UNVERIFIED",
                           "REFUSED_REGISTRY_AUTHENTICATION_REQUIRED"]):
    case("plugin " + state, PLUGIN, facts([1], scopes={"plugin:java-arch": {"1": runs([[look(FRESH, ident=3), state]])}}))
case("plugin not applicable everywhere", PLUGIN, facts([1, 2], scopes={"plugin:java-arch": {
    "1": runs([[look(FRESH), "NOT_APPLICABLE"]]), "2": runs([[look(FRESH), "NOT_APPLICABLE"]])}}))
case("plugin not applicable on one", PLUGIN, facts([1, 2], scopes={"plugin:java-arch": {
    "1": runs([[look(FRESH, ident=5), "PRODUCED", ["java"]]]), "2": runs([[look(FRESH, ident=6), "NOT_APPLICABLE"]])}},
    counts={"plugin:java-arch": {"2": [["high", "open", 5]]}},
    languages={"5": {"detected": ["java"], "sast": []}}))
case("plugin absent beside not applicable", PLUGIN, facts([1], scopes={"plugin:java-arch": {"1": runs(
    [[look(FRESH), "NOT_APPLICABLE"], [look(FRESH_EARLIER), "ABSENT"]], 2)}}))
case("plugin scans ran without it", PLUGIN, facts([1], scopes={"plugin:java-arch": {"1": runs([], 3, True)}}))
case("plugin named before", PLUGIN, facts([1], scopes={"plugin:java-arch": {"1": runs([], 0, True)}}))
case("plugin never", PLUGIN, facts([1], scopes={"plugin:java-arch": {"1": runs([], 0, False)}}))
case("plugin crashed since refusal", PLUGIN, facts([1], scopes={"plugin:java-arch": {"1": runs(
    [[look(FRESH_EARLIER), "REFUSED_UNSIGNED"], [look(FRESH), "ABSENT"]], 2)}}))
case("plugin signed since", PLUGIN, facts([1], scopes={"plugin:java-arch": {"1": runs(
    [[look(FRESH_EARLIER, ident=2), "REFUSED_UNSIGNED"], [look(FRESH, ident=7), "PRODUCED", ["java", "kotlin"]]], 2)}},
    languages={"7": {"detected": ["java", "typescript", "json"], "sast": None}}))
case("plugin old run only", PLUGIN, facts([1], scopes={"plugin:java-arch": {"1": runs([[look(OLD), "PRODUCED", ["java"]]], 0)}}))
case("plugin no census", PLUGIN, facts([1], scopes={"plugin:java-arch": {"1": runs([[look(FRESH, ident=8), "PRODUCED", ["java"]]])}}))
case("plugin census unrecorded", PLUGIN, facts([1], scopes={"plugin:java-arch": {"1": runs([[look(FRESH, ident=8), "PRODUCED", ["java"]]])}},
     languages={"8": {"detected": None, "sast": ["java"]}}))
case("plugin manifest unknown", PLUGIN, facts([1], scopes={"plugin:java-arch": {"1": runs([[look(FRESH, ident=8), "PRODUCED"]])}},
     languages={"8": {"detected": ["java"], "sast": None}}))
case("plugin reads none of the tree", PLUGIN, facts([1], scopes={"plugin:java-arch": {"1": runs([[look(FRESH, ident=8), "PRODUCED", ["python"]]])}},
     languages={"8": {"detected": ["java", "yaml"], "sast": None}}))
case("plugin reads nothing declared", PLUGIN, facts([1], scopes={"plugin:java-arch": {"1": runs([[look(FRESH, ident=8), "PRODUCED", []]])}},
     languages={"8": {"detected": [], "sast": None}}))
case("sast examined", SAST, facts([1], scopes={"builtin:sast": {"1": scanned(look(FRESH, ident=9))}},
     languages={"9": {"detected": ["java", "yaml"], "sast": ["java", "python"]}},
     counts={"builtin:sast": {"1": [["medium", "resolved", 3], ["medium", "open", 2]]}}))
case("sast ratio under", SAST, facts([1], scopes={"builtin:sast": {"1": scanned(look(FRESH, ident=9))}},
     languages={"9": {"detected": ["java"], "sast": ["java"]}},
     counts={"builtin:sast": {"1": [["medium", "resolved", 2], ["medium", "open", 3]]}}))
case("sast nothing of the severity", SAST, facts([1], scopes={"builtin:sast": {"1": scanned(look(FRESH, ident=9))}},
     languages={"9": {"detected": ["java"], "sast": ["java"]}}))
case("sast no census", SAST, facts([1], scopes={"builtin:sast": {"1": scanned(look(FRESH, ident=9))}}))
case("sast no rules recorded", SAST, facts([1], scopes={"builtin:sast": {"1": scanned(look(FRESH, ident=9))}},
     languages={"9": {"detected": ["java"], "sast": None}}))
case("sast no source language", SAST, facts([1], scopes={"builtin:sast": {"1": scanned(look(FRESH, ident=9))}},
     languages={"9": {"detected": ["yaml", "json"], "sast": ["java"]}}))
case("sast empty census", SAST, facts([1], scopes={"builtin:sast": {"1": scanned(look(FRESH, ident=9))}},
     languages={"9": {"detected": [], "sast": []}}))
case("sast unread language", SAST, facts([1, 2], scopes={"builtin:sast": {"1": scanned(look(FRESH, ident=9)),
                                                                        "2": scanned(look(FRESH, ident=10))}},
     languages={"9": {"detected": ["java", "typescript", "bash", "dockerfile"], "sast": ["java"]},
                "10": {"detected": ["go"], "sast": ["go"]}}))
case("quality reads languages too",
     '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:quality"],"thresholds":{"low":{"maxOpen":10}}}',
     facts([1], scopes={"builtin:quality": {"1": scanned(look(FRESH, ident=9))}},
           languages={"9": {"detected": ["ruby"], "sast": ["ruby"]}}))
case("import examined", IMPORTS, facts([1], scopes={"import:ledger-ci/eslint": {
    "1": {"imported": {"newest": look(FRESH, "sarif_import", 9, "ab"), "unrecorded": False}}}}))
case("import unrecorded", IMPORTS, facts([1], scopes={"import:ledger-ci/eslint": {
    "1": {"imported": {"newest": None, "unrecorded": True}}}}))
case("import stale", IMPORTS, facts([1], scopes={"import:ledger-ci/eslint": {
    "1": {"imported": {"newest": look(OLD, "sarif_import", 9, None), "unrecorded": False}}}}))
case("import never", IMPORTS, facts([1], scopes={"import:ledger-ci/eslint": {
    "1": {"imported": {"newest": None, "unrecorded": False}}}}))
case("dependencies pass", DEPS, facts([1], scopes={vuln: {"1": scanned(look(FRESH))}}, scheduled={"1": True}))
case("dependencies unscheduled no sbom", DEPS, facts([1], scopes={vuln: {"1": scanned(look(FRESH), False)}}))
case("dependencies threshold", DEPS_T, facts([1, 2], scopes={vuln: {"1": scanned(look(FRESH)), "2": scanned(look(FRESH))}},
     scheduled={"1": True, "2": True}, counts={vuln: {"1": [["critical", "open", 2]]}}))
case("dependencies plugin facts", DEPS, facts([1], scopes={vuln: {"1": runs([[look(FRESH), "PRODUCED", ["java"]]])}},
     scheduled={"1": True}, languages={"1": {"detected": ["java"], "sast": None}}))
case("dependencies one day", DEPS_T, facts([1], scopes={vuln: {"1": scanned(look(FRESH))}}, scheduled={"1": False}))

cov = lambda ident, at, lc, lt, bc=None, bt=None, packages=None, digest="aa": {
    "look": look(at, "coverage_import", ident, digest), "lines": [lc, lt],
    "branches": None if bc is None else [bc, bt], "packages": packages}
case("coverage per repository", LINES, facts([1, 2], coverage={"1": cov(1, FRESH, 900, 1000), "2": cov(2, FRESH, 70, 100, 1, 2)}))
case("coverage weighted", WEIGHTED, facts([1, 2], coverage={"1": cov(1, FRESH, 900, 1000), "2": cov(2, FRESH, 70, 100, 1, 2)}))
case("coverage weighted under", WEIGHTED, facts([1, 2], coverage={"1": cov(1, FRESH, 10, 1000), "2": cov(2, FRESH, 70, 100)}))
case("coverage weighted partial", WEIGHTED, facts([1, 2], coverage={"1": cov(1, FRESH, 10, 1000)}))
case("coverage branches", BRANCHES, facts([1, 2], coverage={"1": cov(1, FRESH, 900, 1000), "2": cov(2, FRESH, 70, 100, 1, 2)}))
case("coverage branches met", BRANCHES, facts([1], coverage={"1": cov(1, FRESH, 0, 0, 1, 2)}))
case("coverage stale", LINES, facts([1], coverage={"1": cov(1, OLD, 1, 1, digest=None)}))
case("coverage counted nothing", LINES, facts([1], coverage={"1": cov(1, FRESH, 0, 0)}))
case("coverage exact ratio", LINES, facts([1], coverage={"1": cov(1, FRESH, 4, 5)}))
case("coverage just under", LINES, facts([1], coverage={"1": cov(1, FRESH, 79999, 100000)}))
pk = lambda path, lc, lt, bc=None, bt=None: [path, lc, lt, bc, bt]
case("scoped kept", SCOPED, facts([1], coverage={"1": cov(1, FRESH, 100, 200, packages=[
    pk("org/example/service", 30, 40), pk("org/example/service/generated", 0, 50), pk("org/example/web", 0, 100),
    pk("service", 10, 10)])}))
case("scoped under", SCOPED, facts([1], coverage={"1": cov(1, FRESH, 100, 200, packages=[
    pk("org/example/service", 10, 40), pk("org/example/web", 0, 100)])}))
case("scoped matches nothing", SCOPED, facts([1], coverage={"1": cov(1, FRESH, 100, 200, packages=[pk("org/example/web", 0, 100)])}))
case("scoped matches nothing one", SCOPED, facts([1], coverage={"1": cov(1, FRESH, 100, 200, packages=[])}))
case("scoped unrecorded", SCOPED, facts([1], coverage={"1": cov(1, FRESH, 100, 200, packages="unrecorded")}))
case("scoped not kept", SCOPED, facts([1], coverage={"1": cov(1, FRESH, 100, 200, packages={"notKept": "more than 2000 packages"})}))
case("scoped not read", SCOPED, facts([1], coverage={"1": cov(1, FRESH, 100, 200, packages=None)}))
case("scoped counts nothing", SCOPED, facts([1], coverage={"1": cov(1, FRESH, 100, 200, packages=[pk("a/service", 0, 0)])}))
case("scoped branch weighted", SCOPED_BRANCH, facts([1, 2], coverage={
    "1": cov(1, FRESH, 1, 1, 3, 4, packages=[pk("org/a", 1, 1, 3, 4), pk("org/b", 1, 1, None, None)]),
    "2": cov(2, FRESH, 1, 1, 1, 8, packages=[pk("org/c", 1, 1, 1, 8)])}))
case("scoped branch none counted", SCOPED_BRANCH, facts([1], coverage={
    "1": cov(1, FRESH, 1, 1, 0, 0, packages=[pk("org/a", 1, 1, None, None)])}))
case("coverage never", LINES, facts([1, 2], coverage={"2": cov(2, FRESH, 1, 1)}))

tr = lambda suites, at=FRESH: {"look": look(at, "test_report_import", 5, "cc"), "suites": suites}
case("tests none match", TESTS, facts([1], tests={"1": tr([["com.example.AppTest", 9, 0, 0, 0]])}))
case("tests all skipped", TESTS, facts([1], tests={"1": tr([["com.example.arch.LayersTest", 4, 0, 0, 4]])}))
case("tests failed", TESTS, facts([1], tests={"1": tr([["com.example.arch.LayersTest", 4, 1, 2, 0]])}))
case("tests too few", TESTS, facts([1], tests={"1": tr([["com.example.arch.LayersTest", 4, 0, 0, 2]])}))
case("tests pass", TESTS, facts([1], tests={"1": tr([["com.example.arch.LayersTest", 4, 0, 0, 0],
                                                     ["com.example.arch.CyclesTest", 2, 0, 0, 0]])}))
case("tests stale", TESTS, facts([1], tests={"1": tr([], OLD)}))
case("tests never", TESTS, facts([1]))
unit = ["com.example.LedgerTest", 40, 0, 0, 0]
case("several unit only", TESTS2, facts([1], tests={"1": tr([unit])}))
case("several too few", TESTS2, facts([1], tests={"1": tr([unit, ["com.example.LedgerIT", 2, 0, 0, 0]])}))
case("several failed", TESTS2, facts([1], tests={"1": tr([unit, ["com.example.LedgerIT", 5, 1, 0, 0]])}))
case("several skipped", TESTS2, facts([1], tests={"1": tr([unit, ["com.example.LedgerIT", 5, 0, 0, 5]])}))
case("several pass", TESTS2, facts([1], tests={"1": tr([unit, ["com.example.LedgerIT", 5, 0, 0, 0]])}))

comp = lambda name, version, purl: [name, version, purl]
v1 = {vuln: {"1": scanned(look(FRESH))}}
case("components pass", COMPONENTS, facts([1], scopes=v1, components={"1": [
    comp("ledger-core", "3.2.1", "pkg:maven/com.example/ledger-core@3.2.1"), comp("audit", "1.0", "pkg:maven/com.example/audit@1.0")]}))
case("components refused", COMPONENTS, facts([1], scopes=v1, components={"1": [
    comp("ledger-core", "3.2.1", "pkg:maven/com.example/ledger-core@3.2.1"),
    comp("ledger-core", "2.0.0", "pkg:maven/com.example/ledger-core@2.0.0"), comp("audit", "1.0", "pkg:maven/com.example/audit@1.0")]}))
for unstated in ["UNKNOWN", None, " ", " unknown "]:
    case("components unstated %r" % unstated, COMPONENTS, facts([1], scopes=v1, components={"1": [
        comp("ledger-core", unstated, "pkg:maven/com.example/ledger-core"), comp("audit", "1.0", "pkg:maven/com.example/audit@1.0")]}))
case("components mixed stated", COMPONENTS, facts([1], scopes=v1, components={"1": [
    comp("ledger-core", "UNKNOWN", "pkg:maven/com.example/ledger-core"), comp("audit", "1.0", "pkg:maven/com.example/audit@1.0"),
    comp("ledger-core", "3.2.1", "pkg:maven/com.example/ledger-core@3.2.1")]}))
case("components missing beside unstated", COMPONENTS, facts([1], scopes=v1, components={"1": [
    comp("ledger-core", "UNKNOWN", "pkg:maven/com.example/ledger-core")]}))
case("components absent inventory", COMPONENTS, facts([1], scopes={vuln: {"1": scanned(look(FRESH), False)}}))
case("components empty but sbom", COMPONENTS, facts([1], scopes=v1))
case("components stale", COMPONENTS, facts([1], scopes={vuln: {"1": scanned(look(OLD))}}))
fam = [comp("p%02d" % n, "1.%d" % (n % 3), "pkg:maven/org.example.platform/p%02d@1.%d?type=jar" % (n, n % 3)) for n in range(23)]
case("ranged family", RANGED, facts([1], scopes=v1, components={"1": fam + [
    comp("platform", "1.17.7", "pkg:maven/org.example.platform@1.17.7"),
    comp("x", "UNKNOWN", "pkg:maven/org.example.platform/p00#sub")]}))
for version in ["1.17", "1.17.7", "1.99", "2.0-SNAPSHOT", "2.0", "0.9.1", "1.17-rc1"]:
    case("range at " + version, RANGED, facts([1], scopes=v1, components={"1": [
        comp("platform", version, "pkg:maven/org.example.platform@" + version)]}))
case("stored npm range", NPM_RANGE_STORED, facts([1], scopes=v1, components={"1": [
    comp("left", "1.5", "pkg:npm/left@1.5"), comp("left", "1.6", "pkg:npm/left@1.6"),
    comp("left-pad", "9", "pkg:npm/left-pad@9")]}), stored=True)
case("stored separator", SEPARATOR_STORED, facts([1], scopes=v1, components={"1": [
    comp("a", "1", "pkg:maven/org.example/a@1")]}), stored=True)
case("present pass", PRESENT, facts([1, 2], scopes={vuln: {"1": scanned(look(FRESH, ident=1)), "2": scanned(look(FRESH, ident=2), False)}},
     components={"1": [comp("platform", "1.0", "pkg:maven/org.example.platform@1.0"), comp("left", None, "pkg:npm/left")],
                 "2": [comp("platform", "UNKNOWN", "pkg:maven/org.example.platform/a"), comp("platform", "2", "pkg:maven/org.example.platform/a@2"),
                       comp("left", "1", "pkg:npm/left@1")]}))
case("present missing", PRESENT, facts([1], scopes=v1, components={"1": [comp("left-pad", "1", "pkg:npm/left-pad@1")]}))
case("present absent inventory", PRESENT, facts([1], scopes={vuln: {"1": scanned(look(FRESH), False)}}))

R = lambda look_, evidence: {"read": {"look": look_, "evidence": evidence}}
fl = lambda at, ident=31: look(at, "forge_review", ident, None)


def evidence(forge="gitlab", settings=None, settings_unread=None, history=None, history_unread=None, window=30):
    return json.dumps({"forge": forge, "project": "group/ledger", "branch": "main", "windowDays": window,
                       "settings": settings, "settingsUnread": settings_unread, "history": history,
                       "historyUnread": history_unread}, separators=(",", ":"))


strict = {"requiredApprovals": 2, "authorApprovalPrevented": True, "directPushRefused": True,
          "described": "2 approvals required, author's own refused, direct pushes refused"}
loose = {"requiredApprovals": 1, "authorApprovalPrevented": False, "directPushRefused": True, "described": "1 approval"}
chg = lambda ref, at, peers, self_=False: {"reference": ref, "mergedAt": at, "peerApprovals": peers, "authorApproved": self_}
case("review never read", REVIEW, facts([1]))
case("review unlinked", REVIEW, facts([1], reviews={"1": {"unlinked": {"look": fl(FRESH), "why": "no forge connection"}}}))
case("review unreadable", REVIEW, facts([1], reviews={"1": {"unreadable": {"look": fl(FRESH), "why": "token refused"}}}))
case("review unreadable stale", REVIEW, facts([1], reviews={"1": {"unreadable": {"look": fl(OLD), "why": "token refused"}}}))
case("review stale", REVIEW, facts([1], reviews={"1": R(fl(OLD), evidence(settings=strict, history_unread="x"))}))
case("review settings prove", REVIEW, facts([1], reviews={"1": R(fl(FRESH), evidence(settings=strict, history_unread="not asked"))}))
case("review no history", REVIEW, facts([1], reviews={"1": R(fl(FRESH), evidence(settings=loose, history_unread="404"))}))
case("review no history no settings", REVIEW, facts([1], reviews={"1": R(fl(FRESH), evidence(settings_unread="CE", history_unread="404"))}))
case("review incomplete", REVIEW, facts([1], reviews={"1": R(fl(FRESH), evidence(
    "github", settings_unread="plan", history={"complete": False, "changes": [chg("#1", FRESH, 1)]}))}))
case("review short window", REVIEW, facts([1], reviews={"1": R(fl(FRESH), evidence(
    settings_unread="CE", history={"complete": True, "changes": []}, window=14))}))
case("review nothing merged", REVIEW, facts([1], reviews={"1": R(fl(FRESH), evidence(
    settings_unread="CE", history={"complete": True, "changes": [chg("!1", OLD, 1)]}, window=60))}))
case("review nothing merged github", REVIEW, facts([1], reviews={"1": R(fl(FRESH), evidence(
    "github", settings=loose, history={"complete": True, "changes": []}))}))
many_changes = [chg("!%d" % n, FRESH, 0 if n % 2 else 1, n % 5 == 0) for n in range(1, 26)]
case("review history fail", REVIEW, facts([1], reviews={"1": R(fl(FRESH), evidence(
    settings=loose, history={"complete": True, "changes": many_changes}))}))
case("review history pass", REVIEW, facts([1, 2], reviews={
    "1": R(fl(FRESH, 31), evidence(settings_unread="CE", history={"complete": True, "changes": [chg("!1", FRESH, 1), chg("!2", OLDER, 2, True)]})),
    "2": R(fl(OLDER, 32), evidence("github", settings=strict, history_unread="not read"))}))
case("review two peers half", REVIEW2, facts([1], reviews={"1": R(fl(FRESH), evidence(
    "github", settings=loose, history={"complete": True, "changes": [chg("#1", FRESH, 2), chg("#2", FRESH, 1),
                                                                      chg("#3", "2026-09-10T00:00:00Z", 0)]}))}))
case("review two peers under", REVIEW2, facts([1], reviews={"1": R(fl(FRESH), evidence(
    "github", settings=loose, history={"complete": True, "changes": [chg("#1", FRESH, 2), chg("#2", FRESH, 1), chg("#3", FRESH, 0)]}))}))
case("review settings unread unknown", REVIEW, facts([1], reviews={"1": R(fl(FRESH), evidence(settings_unread="", history={"complete": True, "changes": [chg("!1", FRESH, 1)]}))}))
case("many repositories fail", '{"kind":"findings_threshold","maxAgeDays":7,"scopes":["builtin:secret"],"thresholds":{"high":{"maxOpen":0}}}',
     facts(list(range(1, 15)), scopes={"builtin:secret": {str(n): scanned(look(FRESH, ident=n)) for n in range(1, 15)}},
           counts={"builtin:secret": {str(n): [["high", "open", n]] for n in range(1, 15)}}))
case("many repositories pass figures", REVIEW, facts(list(range(1, 13)), reviews={
    str(n): R(fl(FRESH, n), evidence(settings=strict, history_unread="n")) for n in range(1, 13)}))
case("nanosecond as of", SECRETS, facts([1, 2], scopes={"builtin:secret": {
    "1": scanned(look("2026-09-28T12:00:00.000000001Z")), "2": scanned(look("2026-09-28T12:00:00.100Z", ident=2))}}))
out["evaluations"] = ev

# Stored measurements read back and written again, and stored change-review readings.
out["storedMeasurements"] = [
    '{"outcome":"pass","reason":null,"asOf":"2026-09-28T12:00:00Z","repositories":[{"repositoryId":1,"scope":null,'
    '"status":"examined","source":"scan","sourceId":4,"at":"2026-09-28T12:00:00Z","digest":null,"met":true,"detail":null}],'
    '"figures":[],"summary":"Pass."}',
    '{"outcome":"no_data","reason":"some_future_reason","asOf":null,"repositories":[],"figures":[{"scope":"all",'
    '"severity":"high","open":1,"resolved":0,"met":null,"detail":"x"}],"summary":"No data."}',
    '{"outcome":"fail","asOf":null,"repositories":[],"figures":[],"summary":"Fail."}',
    '{"outcome":"maybe","reason":null,"asOf":null,"repositories":[],"figures":[],"summary":""}',
]
out["storedReviews"] = [
    evidence("GitLab", settings=strict, history_unread="x"),
    evidence("github", settings_unread="plan", history={"complete": True, "changes": [chg("#1", "2026-09-28T12:00:00.5Z", 1, True)]}),
    '{"forge":"gitlab","project":"g/p","branch":"main","windowDays":30,"settings":null,"settingsUnread":null,'
    '"history":null,"historyUnread":"x"}',
]

json.dump(out, open(sys.argv[1], "w"), ensure_ascii=False, indent=1)
