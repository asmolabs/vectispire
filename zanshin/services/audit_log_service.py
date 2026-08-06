"""Recording of administration and security-relevant actions.

Three properties matter for a trail to be worth having, and the first version had
only the first:

1. **What happened and who did it.** Was there from the start.
2. **Where from.** An entry said "Alice failed to log in" and nothing else. For
   authentication events that is the difference between "she mistyped it twice" and
   "someone is walking the account list from one host".
3. **Whether it has been edited.** Each entry now carries the hash of the previous
   one, forming a chain: changing or deleting a past entry breaks every hash after
   it. This does *not* make the log append-only — whoever can write the table can
   rewrite the whole chain — but it makes *selective* editing detectable, and
   selective editing is the realistic threat when the interesting record is one line
   among thousands.
"""
import hashlib
import logging
from typing import List, Optional

from zanshin.clock import utcnow

from zanshin.models.audit_log import AuditLog
from zanshin.repositories.audit_log_repository import AuditLogRepository

logger = logging.getLogger(__name__)


class AuditOperation:
    """Known `operation_type` values. Not an exhaustive/enforced enum (the
    column is a plain string) — just a single place to avoid typos/drift
    across the call sites below."""
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    # Attempt refused before any password check, by the rate limiter.
    LOGIN_BLOCKED = "LOGIN_BLOCKED"
    PASSWORD_CHANGED = "PASSWORD_CHANGED"
    USER_CREATED = "USER_CREATED"
    USER_UPDATED = "USER_UPDATED"
    USER_PASSWORD_RESET = "USER_PASSWORD_RESET"
    USER_DELETED = "USER_DELETED"
    API_KEY_CREATED = "API_KEY_CREATED"
    API_KEY_DELETED = "API_KEY_DELETED"
    SETTING_UPDATED = "SETTING_UPDATED"
    # Triage is a security decision (it can suppress a finding), so it belongs
    # in the audit trail alongside user and settings changes.
    ISSUE_TRIAGED = "ISSUE_TRIAGED"
    # A scan reads a repository with its deploy key and can reach the network:
    # who asked for one, and when, belongs in the trail.
    SCAN_TRIGGERED = "SCAN_TRIGGERED"
    # A ticket is created on the operator's behalf by the scheduler, with no human in
    # the loop, so the trail is the only record that Zanshin wrote into the tracker.
    TICKET_CREATED = "TICKET_CREATED"
    # Changing what fails a build is a security decision, and the previous design let
    # each pipeline make it in its own CI file, unrecorded.
    GATE_POLICY_UPDATED = "GATE_POLICY_UPDATED"
    # An authorization refusal was only an application log line, so a probe against
    # every handler left no trace an operator would ever look at.
    ACCESS_DENIED = "ACCESS_DENIED"
    # A deploy key left the control plane for a remote agent (delegated mode only,
    # see ADR-002 §5). If that agent is later found compromised, this is the only
    # record of which keys it was given.
    AGENT_CREDENTIAL_SENT = "AGENT_CREDENTIAL_SENT"
    # An agent submitted scan results. Audited like a triage, because both change
    # the finding set a gate is evaluated against.
    AGENT_RESULT_SUBMITTED = "AGENT_RESULT_SUBMITTED"
    # Registering, disabling or deleting an agent changes who may run scans.
    AGENT_CREATED = "AGENT_CREATED"
    AGENT_UPDATED = "AGENT_UPDATED"
    AGENT_DELETED = "AGENT_DELETED"


class AuditLogService:
    """Records administration/security-relevant actions to `audit_logs`.

    Deliberately scoped to admin/security actions (auth, user management, API key
    lifecycle, settings changes, triage, scan triggers, authorization refusals) —
    not page views, which would just be noise.

    `record()` never raises: a logging failure must not break the action it's
    describing. Called from the UI state layer (not from deeper services) because
    that's where the acting user's identity is already available.
    """

    def __init__(self, audit_log_repository: AuditLogRepository):
        self.audit_log_repository = audit_log_repository

    def record(
        self,
        operation_type: str,
        resource_id: str,
        description: str,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> None:
        try:
            previous = self.audit_log_repository.find_latest()
            entry = AuditLog(
                # Set here, not left to the column default: the hash covers the
                # timestamp, and a default applied at flush time would be assigned
                # *after* the hash was computed — so every entry would fail its own
                # verification.
                timestamp=utcnow(),
                operation_type=operation_type,
                resource_id=str(resource_id),
                description=description[:255],
                user_id=user_id,
                ip_address=(ip_address or None),
                user_agent=(user_agent or "")[:255] or None,
                previous_hash=previous.entry_hash if previous else None,
            )
            entry.entry_hash = compute_entry_hash(entry)
            self.audit_log_repository.save(entry)
        except Exception:
            logger.exception(
                "Failed to write audit log entry (operation=%s, resource=%s) — continuing",
                operation_type, resource_id
            )

    def find_recent(self, limit: int = 200) -> List[AuditLog]:
        return self.audit_log_repository.find_recent(limit)

    def verify_chain(self) -> Optional[str]:
        """`None` if the chain is intact, or a description of the first break.

        Reads the whole table oldest-first, so it is a deliberate check rather than
        something done on every page render. Entries written before the chain existed
        carry no hash and are skipped — with the gap reported, because "we cannot
        verify these" is information, not an absence of it.
        """
        entries = self.audit_log_repository.find_all_oldest_first()
        unverifiable = 0
        expected_previous: Optional[str] = None
        started = False

        for entry in entries:
            if not entry.entry_hash:
                if started:
                    return (
                        f"Entrée {entry.id} sans empreinte alors que le chaînage avait "
                        "commencé : la ligne a été insérée ou modifiée."
                    )
                unverifiable += 1
                continue

            if started and entry.previous_hash != expected_previous:
                return (
                    f"Entrée {entry.id} : empreinte précédente {entry.previous_hash!r}, "
                    f"attendue {expected_previous!r} — une entrée antérieure a été "
                    "modifiée ou supprimée."
                )
            if entry.entry_hash != compute_entry_hash(entry):
                return f"Entrée {entry.id} : son propre contenu ne correspond plus à son empreinte."

            started = True
            expected_previous = entry.entry_hash

        if unverifiable:
            logger.info(
                "%d audit entries predate the integrity chain and cannot be verified",
                unverifiable,
            )
        return None


def compute_entry_hash(entry: AuditLog) -> str:
    """`H(previous_hash | timestamp | operation | resource | user | ip | description)`.

    Field order and separator are fixed: a hash whose input depends on dict ordering
    would fail verification for reasons that have nothing to do with tampering. The
    separator is a NUL byte so no field's content can imitate a boundary — otherwise
    a description ending in the right characters could shift the meaning of the next
    field.
    """
    parts = [
        entry.previous_hash or "",
        entry.timestamp.isoformat() if entry.timestamp else "",
        entry.operation_type or "",
        entry.resource_id or "",
        entry.user_id or "",
        entry.ip_address or "",
        entry.user_agent or "",
        entry.description or "",
    ]
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()
