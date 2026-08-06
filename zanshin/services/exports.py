"""Export formats for issues: OpenVEX and CSV.

VEX was the point of storing triage decisions in the standard's vocabulary rather
than in free text — so this is a serialization, not a translation. Every field an
OpenVEX statement needs (status, justification, timestamps, product identity) is
already on `Issue`; nothing here has to infer or invent anything, which is what
makes the output trustworthy enough to hand to a customer or an auditor.

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
    "package_name", "package_version", "purl", "file_path", "fix_state",
    "fix_versions", "state", "triage_status", "triage_justification",
    "triaged_by", "triaged_at", "first_seen_at", "last_seen_at", "times_seen",
    "link",
]


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
                "file_path": issue.file_path or "",
                "fix_state": issue.fix_state or "",
                "fix_versions": issue.fix_versions or "",
                "state": issue.state,
                "triage_status": issue.triage_status,
                "triage_justification": issue.triage_justification or "",
                "triaged_by": issue.triaged_by or "",
                "triaged_at": _isoformat(issue.triaged_at),
                "first_seen_at": _isoformat(issue.first_seen_at),
                "last_seen_at": _isoformat(issue.last_seen_at),
                "times_seen": issue.times_seen or 1,
                "link": issue.link or "",
            }
        )
    return buffer.getvalue()


def _number(value: Optional[float]) -> str:
    return "" if value is None else str(value)


def _isoformat(value) -> str:
    return value.isoformat() if value else ""
