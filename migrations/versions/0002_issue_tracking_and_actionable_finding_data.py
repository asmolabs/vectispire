"""issue tracking and actionable finding data

Adds the cross-scan `issue` table (see zanshin/models/issue.py), links findings
to it, records the per-scan delta, and stores the fix/CVSS data the scanners
already produced and the pipeline was discarding.

Hand-trimmed from autogenerate output. The full diff also reported pre-existing
drift between the models and the tables the *previous* implementation created
(`user`/`vex_decision`/`api_key` timestamps typed `TIMESTAMP` instead of
`SafeDateTime`, missing indexes and unique constraints). None of it is touched
here: on SQLite those type differences are storage-identical, and rewriting
populated tables to add constraints is a separate, deliberate operation — not a
side effect of shipping issue tracking. It is recorded in ADR-001 instead.

Existing `finding` rows are backfilled into issues so that history isn't lost:
the first scan run after this migration would otherwise report every
long-standing problem as "new".

Revision ID: 0002
Revises: 0001
Create Date: 2026-08-06
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# The models use custom column types (`GUID`, `SafeDateTime`); autogenerate
# renders them by their fully-qualified name, so these modules must be
# importable from every migration.
import zanshin.models.guid
import zanshin.models.safedatetime

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "issue",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("repo_id", sa.BigInteger(), nullable=True),
        sa.Column("container_id", sa.BigInteger(), nullable=True),
        sa.Column("fingerprint", sa.String(length=64), nullable=False),
        sa.Column("type", sa.String(length=50), nullable=False),
        sa.Column("identifier", sa.String(length=255), nullable=True),
        sa.Column("package_name", sa.String(length=255), nullable=True),
        sa.Column("package_version", sa.String(length=255), nullable=True),
        sa.Column("purl", sa.String(length=255), nullable=True),
        sa.Column("file_path", sa.String(length=500), nullable=True),
        sa.Column("source", sa.String(length=50), nullable=True),
        sa.Column("severity", sa.String(length=50), nullable=True),
        sa.Column("epss_score", sa.Float(), nullable=True),
        sa.Column("is_kev", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(length=255), nullable=True),
        sa.Column("fix_state", sa.String(length=50), nullable=True),
        sa.Column("fix_versions", sa.String(length=255), nullable=True),
        sa.Column("link", sa.String(length=500), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("state", sa.String(length=20), nullable=False, server_default="open"),
        sa.Column("first_seen_at", zanshin.models.safedatetime.SafeDateTime(), nullable=False),
        sa.Column("last_seen_at", zanshin.models.safedatetime.SafeDateTime(), nullable=False),
        sa.Column("resolved_at", zanshin.models.safedatetime.SafeDateTime(), nullable=True),
        sa.Column("first_seen_scan_id", sa.BigInteger(), nullable=True),
        sa.Column("last_seen_scan_id", sa.BigInteger(), nullable=True),
        sa.Column("times_seen", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("triage_status", sa.String(length=30), nullable=False, server_default="under_review"),
        sa.Column("triage_justification", sa.String(length=64), nullable=True),
        sa.Column("triage_comment", sa.Text(), nullable=True),
        sa.Column("triaged_by", sa.String(length=255), nullable=True),
        sa.Column("triaged_at", zanshin.models.safedatetime.SafeDateTime(), nullable=True),
        sa.ForeignKeyConstraint(["container_id"], ["container.id"]),
        sa.ForeignKeyConstraint(["first_seen_scan_id"], ["scan.id"]),
        sa.ForeignKeyConstraint(["last_seen_scan_id"], ["scan.id"]),
        sa.ForeignKeyConstraint(["repo_id"], ["repository.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("fingerprint", name="uq_issue_fingerprint"),
    )
    with op.batch_alter_table("issue", schema=None) as batch_op:
        batch_op.create_index(batch_op.f("ix_issue_fingerprint"), ["fingerprint"], unique=False)
        batch_op.create_index(batch_op.f("ix_issue_id"), ["id"], unique=False)
        # The two queries the issues screen runs constantly: "everything
        # outstanding on this target" and "everything outstanding, by severity".
        batch_op.create_index("ix_issue_repo_state", ["repo_id", "state"], unique=False)
        batch_op.create_index("ix_issue_container_state", ["container_id", "state"], unique=False)

    with op.batch_alter_table("finding", schema=None) as batch_op:
        batch_op.add_column(sa.Column("cvss_score", sa.Float(), nullable=True))
        batch_op.add_column(sa.Column("cvss_vector", sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column("fix_state", sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column("fix_versions", sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column("link", sa.String(length=500), nullable=True))
        batch_op.add_column(sa.Column("issue_id", sa.Integer(), nullable=True))
        batch_op.create_index(batch_op.f("ix_finding_issue_id"), ["issue_id"], unique=False)
        batch_op.create_foreign_key("fk_finding_issue_id", "issue", ["issue_id"], ["id"])

    with op.batch_alter_table("scan", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("new_issues_count", sa.Integer(), nullable=False, server_default="0")
        )
        batch_op.add_column(
            sa.Column("resolved_issues_count", sa.Integer(), nullable=False, server_default="0")
        )

    _backfill_issues_from_findings()


def _backfill_issues_from_findings() -> None:
    """Rebuild issue history from the findings already stored.

    Without this, every problem a deployment has been carrying for months would
    be reported as "new" by the first scan after this upgrade — the exact signal
    the feature exists to make trustworthy. Replays findings oldest-scan-first,
    so `first_seen`/`last_seen`/`times_seen` come out as if issues had always
    been tracked. Issues whose last sighting isn't the target's latest scan are
    marked resolved, again as the pipeline would have.

    Deliberately reuses the application's own `build_fingerprint` rather than
    reimplementing the hash in SQL: two definitions of identity would drift, and
    the fingerprints written here must match the ones the running code produces.
    """
    from zanshin.models.issue import STATE_OPEN, STATE_RESOLVED, build_fingerprint

    bind = op.get_bind()

    findings = bind.execute(
        sa.text(
            """
            SELECT f.id, f.type, f.identifier, f.package_name, f.package_version,
                   f.purl, f.file_path, f.source, f.severity, f.epss_score, f.is_kev,
                   s.id AS scan_id, s.repo_id, s.container_id, s.created_at
              FROM finding f
              JOIN scan s ON s.id = f.scan_id
             ORDER BY s.created_at ASC, s.id ASC, f.id ASC
            """
        )
    ).mappings().all()
    if not findings:
        return

    issues: dict = {}
    finding_links: list = []
    for row in findings:
        fingerprint = build_fingerprint(
            repo_id=row["repo_id"],
            container_id=row["container_id"],
            finding_type=row["type"],
            identifier=row["identifier"],
            purl=row["purl"],
            package_name=row["package_name"],
            file_path=row["file_path"],
        )
        issue = issues.get(fingerprint)
        if issue is None:
            issue = {
                "fingerprint": fingerprint,
                "repo_id": row["repo_id"],
                "container_id": row["container_id"],
                "type": row["type"],
                "identifier": row["identifier"],
                "package_name": row["package_name"],
                "package_version": row["package_version"],
                "purl": row["purl"],
                "file_path": row["file_path"],
                "source": row["source"],
                "severity": row["severity"],
                "epss_score": row["epss_score"],
                "is_kev": row["is_kev"] or 0,
                "first_seen_at": row["created_at"],
                "last_seen_at": row["created_at"],
                "first_seen_scan_id": row["scan_id"],
                "last_seen_scan_id": row["scan_id"],
                "times_seen": 1,
                "_scans": {row["scan_id"]},
            }
            issues[fingerprint] = issue
        else:
            # Latest sighting wins for the mutable assessment fields.
            issue["package_version"] = row["package_version"]
            issue["severity"] = row["severity"]
            issue["epss_score"] = row["epss_score"]
            issue["is_kev"] = row["is_kev"] or 0
            issue["last_seen_at"] = row["created_at"]
            issue["last_seen_scan_id"] = row["scan_id"]
            if row["scan_id"] not in issue["_scans"]:
                issue["_scans"].add(row["scan_id"])
                issue["times_seen"] += 1
        finding_links.append((row["id"], fingerprint))

    # Latest *successful* scan per target: an issue absent from it is no longer
    # observed. Failed and interrupted scans are excluded on purpose — they
    # observed nothing, so treating them as evidence of absence would silently
    # mark a target's entire backlog "resolved" (which is exactly what happened
    # on the first run of this backfill against a database whose last three
    # scans were stuck in "scanning").
    latest_by_target = {}
    for row in bind.execute(
        sa.text(
            """
            SELECT id, repo_id, container_id, created_at FROM scan
             WHERE status = 'completed'
             ORDER BY created_at ASC, id ASC
            """
        )
    ).mappings():
        key = ("repo", row["repo_id"]) if row["repo_id"] else ("container", row["container_id"])
        latest_by_target[key] = row["id"]

    insert = sa.text(
        """
        INSERT INTO issue (repo_id, container_id, fingerprint, type, identifier,
                           package_name, package_version, purl, file_path, source,
                           severity, epss_score, is_kev, state, first_seen_at,
                           last_seen_at, resolved_at, first_seen_scan_id,
                           last_seen_scan_id, times_seen, triage_status)
        VALUES (:repo_id, :container_id, :fingerprint, :type, :identifier,
                :package_name, :package_version, :purl, :file_path, :source,
                :severity, :epss_score, :is_kev, :state, :first_seen_at,
                :last_seen_at, :resolved_at, :first_seen_scan_id,
                :last_seen_scan_id, :times_seen, 'under_review')
        """
    )
    for issue in issues.values():
        key = (
            ("repo", issue["repo_id"]) if issue["repo_id"] else ("container", issue["container_id"])
        )
        still_seen = latest_by_target.get(key) == issue["last_seen_scan_id"]
        issue["state"] = STATE_OPEN if still_seen else STATE_RESOLVED
        issue["resolved_at"] = None if still_seen else issue["last_seen_at"]
        issue.pop("_scans")
        bind.execute(insert, issue)

    # Link each finding to its issue, in one statement per issue rather than one
    # per finding.
    by_fingerprint = {
        row["fingerprint"]: row["id"]
        for row in bind.execute(sa.text("SELECT id, fingerprint FROM issue")).mappings()
    }
    grouped: dict = {}
    for finding_id, fingerprint in finding_links:
        grouped.setdefault(by_fingerprint[fingerprint], []).append(finding_id)
    for issue_id, finding_ids in grouped.items():
        bind.execute(
            sa.text("UPDATE finding SET issue_id = :issue_id WHERE id IN :ids").bindparams(
                sa.bindparam("ids", expanding=True)
            ),
            {"issue_id": issue_id, "ids": finding_ids},
        )


def downgrade() -> None:
    with op.batch_alter_table("scan", schema=None) as batch_op:
        batch_op.drop_column("resolved_issues_count")
        batch_op.drop_column("new_issues_count")

    with op.batch_alter_table("finding", schema=None) as batch_op:
        batch_op.drop_constraint("fk_finding_issue_id", type_="foreignkey")
        batch_op.drop_index(batch_op.f("ix_finding_issue_id"))
        batch_op.drop_column("issue_id")
        batch_op.drop_column("link")
        batch_op.drop_column("fix_versions")
        batch_op.drop_column("fix_state")
        batch_op.drop_column("cvss_vector")
        batch_op.drop_column("cvss_score")

    with op.batch_alter_table("issue", schema=None) as batch_op:
        batch_op.drop_index("ix_issue_container_state")
        batch_op.drop_index("ix_issue_repo_state")
        batch_op.drop_index(batch_op.f("ix_issue_id"))
        batch_op.drop_index(batch_op.f("ix_issue_fingerprint"))

    op.drop_table("issue")
