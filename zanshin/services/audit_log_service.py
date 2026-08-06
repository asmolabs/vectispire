import logging
from typing import List, Optional

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
    # An authorization refusal was only an application log line, so a probe against
    # every handler left no trace an operator would ever look at.
    ACCESS_DENIED = "ACCESS_DENIED"

class AuditLogService:
    """Records administration/security-relevant actions to `audit_logs` —
    an existing table inherited from an earlier implementation of this
    application, never wired up until now (see AuditLog's docstring).

    Deliberately scoped to admin/security actions (auth, user management,
    API key lifecycle, settings changes) — not scan runs or page views,
    which would just be noise here and are already visible in the scan
    history itself.

    `record()` never raises: a logging failure must not break the action
    it's describing. Called from the UI state layer (not from deeper
    services) because that's where the acting user's identity is already
    available (`BaseState.username`), rather than threading an "actor"
    parameter through every service method.
    """

    def __init__(self, audit_log_repository: AuditLogRepository):
        self.audit_log_repository = audit_log_repository

    def record(
        self,
        operation_type: str,
        resource_id: str,
        description: str,
        user_id: Optional[str] = None,
    ) -> None:
        try:
            entry = AuditLog(
                operation_type=operation_type,
                resource_id=str(resource_id),
                description=description[:255],
                user_id=user_id,
            )
            self.audit_log_repository.save(entry)
        except Exception:
            logger.exception(
                "Failed to write audit log entry (operation=%s, resource=%s) — continuing",
                operation_type, resource_id
            )

    def find_recent(self, limit: int = 200) -> List[AuditLog]:
        return self.audit_log_repository.find_recent(limit)
