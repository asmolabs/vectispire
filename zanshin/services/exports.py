"""Export formats for issues: SARIF, OpenVEX and CSV.

VEX was the point of storing triage decisions in the standard's vocabulary rather
than in free text — so this is a serialization, not a translation. Every field an
OpenVEX statement needs (status, justification, timestamps, product identity) is
already on `Issue`; nothing here has to infer or invent anything, which is what
makes the output trustworthy enough to hand to a customer or an auditor.

SARIF is the odd one out in purpose: OpenVEX and CSV are for people outside the
pipeline (customers, auditors, spreadsheets), while SARIF exists so a finding stops
living only in Zanshin. It is what GitHub code scanning, GitLab and Azure DevOps
ingest natively, which is what puts a problem in front of the developer who
introduced it, annotated on the line, in the pull request — instead of on a
dashboard they have no reason to open.

Pure functions over model objects: the HTTP layer decides how to deliver them,
and a UI download button can reuse them unchanged.
"""
import csv
import io
from typing import Any, Dict, Iterable, List, Optional

from zanshin.models.issue import (
    STATE_RESOLVED,
    TRIAGE_AFFECTED,
    TRIAGE_FIXED,
    TRIAGE_NOT_AFFECTED,
    TRIAGE_UNDER_REVIEW,
    Issue,
)

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"

# Zanshin's triage vocabulary is already OpenVEX's, with one exception:
# `under_review` is spelled `under_investigation` in the specification.
_VEX_STATUS = {
    TRIAGE_UNDER_REVIEW: "under_investigation",
    TRIAGE_AFFECTED: "affected",
    TRIAGE_NOT_AFFECTED: "not_affected",
    TRIAGE_FIXED: "fixed",
}

CSV_COLUMNS = [
    "id", "type", "identifier", "severity", "cvss_score", "epss_score", "is_kev",
    "package_name", "package_version", "purl", "dependency", "file_path", "line",
    "fix_state", "fix_versions", "state", "triage_status", "triage_justification",
    "triaged_by", "triaged_at", "triage_expires_at", "first_seen_at",
    "last_seen_at", "times_seen", "link",
]

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# SARIF has four levels and no notion of "critical". Anything a security tool
# would call critical or high has to land on "error", because "warning" is what a
# reviewer scrolls past.
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "negligible": "note",
    "unknown": "warning",
}

# GitHub ranks and filters on this property, not on `level`, so it is what keeps a
# critical distinguishable from a high once both are "error". The numbers follow
# the CVSS bands GitHub documents.
_SECURITY_SEVERITY = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.5",
    "low": "3.0",
    "negligible": "1.0",
}

_ISSUE_TYPE_LABEL = {
    "vulnerability": "Vulnérabilité",
    "secret": "Secret exposé",
    "iac": "Configuration d'infrastructure",
    "license": "Licence",
    "ai_review": "Revue IA",
}


def build_openvex_document(
    issues: Iterable[Issue],
    *,
    author: str,
    product_id: str,
    document_id: str,
    timestamp: str,
    version: int = 1,
) -> Dict[str, Any]:
    """An OpenVEX document for one product, from its vulnerability issues.

    Only `type="vulnerability"` issues are included: VEX is defined over
    vulnerability identifiers, and a hardcoded secret or a failed IaC check has no
    CVE to make a statement about. Issues without an identifier are skipped for
    the same reason — an anonymous statement isn't one.

    `timestamp`, `document_id` and `author` are supplied by the caller rather than
    computed here: a VEX document is a signed-ish assertion about who said what
    and when, so those belong to whoever is publishing it, not to a helper.
    """
    statements = []
    for issue in issues:
        if issue.type != "vulnerability" or not issue.identifier:
            continue

        statement: Dict[str, Any] = {
            "vulnerability": {"name": issue.identifier},
            "products": [{"@id": product_id}],
            "status": _VEX_STATUS.get(issue.triage_status, "under_investigation"),
        }
        # A resolved-but-never-triaged issue is factually fixed: the scanner
        # stopped seeing it. Saying "under investigation" about something that is
        # gone would be misleading in a document meant to answer exactly that.
        if issue.state == STATE_RESOLVED and issue.triage_status == TRIAGE_UNDER_REVIEW:
            statement["status"] = "fixed"

        if statement["status"] == "not_affected":
            # Required by the specification for this status, and guaranteed
            # present by `IssueService.triage`.
            statement["justification"] = issue.triage_justification
            if issue.triage_comment:
                statement["impact_statement"] = issue.triage_comment
        elif statement["status"] == "affected" and issue.triage_comment:
            # For "affected", free text belongs in the action statement.
            statement["action_statement"] = issue.triage_comment

        if issue.purl:
            statement["products"] = [{"@id": product_id, "identifiers": {"purl": issue.purl}}]
        if issue.triaged_at:
            statement["timestamp"] = issue.triaged_at.isoformat()
        elif issue.last_seen_at:
            statement["timestamp"] = issue.last_seen_at.isoformat()

        statements.append(statement)

    return {
        "@context": OPENVEX_CONTEXT,
        "@id": document_id,
        "author": author,
        "timestamp": timestamp,
        "version": version,
        "tooling": "Zanshin",
        "statements": statements,
    }


def build_sarif_document(
    issues: Iterable[Issue],
    *,
    target_name: str,
    tool_version: str = "1.0.0",
    information_uri: Optional[str] = None,
) -> Dict[str, Any]:
    """A SARIF 2.1.0 log for one target's issues.

    Design decisions worth stating, because SARIF is permissive enough that a
    technically valid document can still be useless in a code-scanning UI:

    * **Triaged issues are `suppressions`, not omissions.** Dropping them would
      make a platform re-report them as new on the next upload, undoing the triage
      work; and a suppression carries the justification, so the reviewer sees *why*
      it was dismissed. `not_affected` and `fixed` are suppressed, `affected` is
      not — a decision that the problem is real must stay visible.
    * **Resolved issues are excluded entirely.** They are gone; SARIF's job here is
      the current state of the branch being built.
    * **`partialFingerprints` carries Zanshin's own fingerprint**, which is what
      lets the platform match an issue across uploads even when the file moves or
      the line shifts — the same identity that keeps triage attached across scans.
    * **Every result gets a location**, falling back to the repository root when a
      dependency issue has no file. GitHub silently drops results without one, so
      an "honest" empty location would mean the vulnerability findings — the bulk
      of them — never appeared at all.

    Rules are emitted per distinct identifier rather than per issue, because that
    is what SARIF's model means by a rule and what lets a platform group findings.
    """
    issues = [issue for issue in issues if issue.state != STATE_RESOLVED]

    rules: Dict[str, Dict[str, Any]] = {}
    rule_index: Dict[str, int] = {}
    results: List[Dict[str, Any]] = []

    for issue in issues:
        rule_id = _sarif_rule_id(issue)
        if rule_id not in rules:
            rule_index[rule_id] = len(rules)
            rules[rule_id] = _sarif_rule(issue, rule_id)

        result: Dict[str, Any] = {
            "ruleId": rule_id,
            "ruleIndex": rule_index[rule_id],
            "level": _SARIF_LEVEL.get((issue.severity or "unknown").lower(), "warning"),
            "message": {"text": _sarif_message(issue)},
            "locations": [_sarif_location(issue)],
            "partialFingerprints": {"zanshinIssueFingerprint": issue.fingerprint},
            "properties": {
                "zanshinIssueId": issue.id,
                "type": issue.type,
                "firstSeen": _isoformat(issue.first_seen_at),
                "timesSeen": issue.times_seen or 1,
            },
        }
        if issue.is_direct_dependency is not None:
            result["properties"]["dependency"] = (
                "direct" if issue.is_direct_dependency else "transitive"
            )
        if _is_suppressed(issue):
            result["suppressions"] = [{
                # "external": the decision was made in Zanshin, not in an
                # annotation in the source, which is what this kind documents.
                "kind": "external",
                "justification": _suppression_justification(issue),
            }]
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {"driver": {
                "name": "Zanshin",
                "version": tool_version,
                **({"informationUri": information_uri} if information_uri else {}),
                "rules": list(rules.values()),
            }},
            "results": results,
            "properties": {"target": target_name},
        }],
    }


def _sarif_rule_id(issue: Issue) -> str:
    """Stable, and namespaced by type.

    A gitleaks rule and a checkov check can collide on an identifier, and a
    platform keyed on `ruleId` would then merge two unrelated classes of problem
    under one heading.
    """
    identifier = issue.identifier or "unspecified"
    return f"zanshin/{issue.type}/{identifier}"


def _sarif_rule(issue: Issue, rule_id: str) -> Dict[str, Any]:
    label = _ISSUE_TYPE_LABEL.get(issue.type, issue.type)
    rule: Dict[str, Any] = {
        "id": rule_id,
        "name": (issue.identifier or issue.type).replace(" ", ""),
        "shortDescription": {"text": f"{label} : {issue.identifier or 'non identifié'}"},
        "properties": {"tags": ["security", issue.type]},
    }
    if issue.description:
        rule["fullDescription"] = {"text": issue.description[:1000]}
    if issue.link:
        rule["helpUri"] = issue.link
    severity = (issue.severity or "").lower()
    if severity in _SECURITY_SEVERITY:
        rule["properties"]["security-severity"] = _SECURITY_SEVERITY[severity]
    return rule


def _sarif_message(issue: Issue) -> str:
    """What the developer reads in the pull request, so it says what to do.

    The fixed version is the single most useful thing to put in front of someone
    who has thirty seconds: it turns "there is a CVE" into "change this line".
    """
    parts = []
    if issue.package_name:
        package = issue.package_name
        if issue.package_version:
            package += f" {issue.package_version}"
        parts.append(package)
    parts.append(issue.identifier or _ISSUE_TYPE_LABEL.get(issue.type, issue.type))
    message = " — ".join(parts)

    if issue.fix_versions:
        message += f" — corrigé dans {issue.fix_versions}"
    elif issue.fix_state == "not-fixed":
        message += " — aucun correctif publié"
    if issue.is_kev:
        message += " — exploitation active connue (CISA KEV)"
    if issue.is_direct_dependency is False:
        message += " — dépendance transitive"
    return message


def _sarif_location(issue: Issue) -> Dict[str, Any]:
    location: Dict[str, Any] = {
        "physicalLocation": {
            # A relative URI, as SARIF requires for source that the consumer
            # resolves against the repository it just checked out.
            "artifactLocation": {"uri": issue.file_path or "."},
        }
    }
    if issue.line:
        location["physicalLocation"]["region"] = {"startLine": int(issue.line)}
    if issue.purl:
        location["logicalLocations"] = [{"name": issue.purl, "kind": "package"}]
    return location


def _is_suppressed(issue: Issue) -> bool:
    return issue.triage_status in (TRIAGE_NOT_AFFECTED, TRIAGE_FIXED)


def _suppression_justification(issue: Issue) -> str:
    parts = [issue.triage_status]
    if issue.triage_justification:
        parts.append(issue.triage_justification)
    if issue.triage_comment:
        parts.append(issue.triage_comment)
    if issue.triaged_by:
        parts.append(f"décidé par {issue.triaged_by}")
    if issue.triage_expires_at:
        parts.append(f"à revoir le {issue.triage_expires_at.date().isoformat()}")
    return " — ".join(parts)


def build_issues_csv(issues: Iterable[Issue]) -> str:
    """Flat CSV of issues, one row each, for reporting and spreadsheets.

    Deliberately one column per stored field rather than a curated subset: the
    people who ask for CSV are the ones who want to pivot it themselves.
    """
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for issue in issues:
        writer.writerow(
            {
                "id": issue.id,
                "type": issue.type,
                "identifier": issue.identifier or "",
                "severity": issue.severity or "",
                "cvss_score": _number(issue.cvss_score),
                "epss_score": _number(issue.epss_score),
                "is_kev": "true" if issue.is_kev else "false",
                "package_name": issue.package_name or "",
                "package_version": issue.package_version or "",
                "purl": issue.purl or "",
                "dependency": _dependency_label(issue.is_direct_dependency),
                "file_path": issue.file_path or "",
                "line": issue.line or "",
                "fix_state": issue.fix_state or "",
                "fix_versions": issue.fix_versions or "",
                "state": issue.state,
                "triage_status": issue.triage_status,
                "triage_justification": issue.triage_justification or "",
                "triaged_by": issue.triaged_by or "",
                "triaged_at": _isoformat(issue.triaged_at),
                "triage_expires_at": _isoformat(issue.triage_expires_at),
                "first_seen_at": _isoformat(issue.first_seen_at),
                "last_seen_at": _isoformat(issue.last_seen_at),
                "times_seen": issue.times_seen or 1,
                "link": issue.link or "",
            }
        )
    return buffer.getvalue()


def _dependency_label(is_direct: Optional[bool]) -> str:
    """Empty rather than "unknown": a column of the word "unknown" reads like a
    finding about the dependency, and the honest statement is that we have nothing
    to say."""
    if is_direct is None:
        return ""
    return "direct" if is_direct else "transitive"


def _number(value: Optional[float]) -> str:
    return "" if value is None else str(value)


def _isoformat(value) -> str:
    return value.isoformat() if value else ""
