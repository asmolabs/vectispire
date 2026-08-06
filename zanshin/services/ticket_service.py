"""Opening a tracker ticket for the problems that would fail a build.

SARIF closed the loop towards the developer: a finding now appears on the pull request
that introduced it. This closes it towards the organisation — a problem that nobody is
going to fix this afternoon needs to exist somewhere people plan work, not only in a
dashboard nobody has a reason to open.

Design decisions, in order of how much they shaped the code:

* **Driven by the gate policy, not by a second threshold.** "Open a ticket for what
  would fail a build" is a rule an operator can already reason about, and it means
  there is exactly one place where "serious enough to act on" is defined. Inventing a
  `ticket_min_severity` would have created two vocabularies that drift apart, and the
  first bug report would be "why did it ticket that but not fail the build".
* **A sweep, not an event.** Notifications fire inline after a scan; tickets do not.
  A sweep over "actionable issues with no ticket" is idempotent by construction — the
  reference stored on the issue *is* the deduplication key — so a tracker that was in
  maintenance gets retried on the next tick instead of losing the ticket silently.
  This is also why no outbox is needed here: the state to reconcile is already in the
  issue row.
* **One ticket per issue, for the issue's whole life.** Not per scan, and not
  reopened when the issue reappears: a tracker ticket that comes back from the dead on
  every rescan is how people learn to mute the project. `Issue.ticket_ref` is set once
  and never cleared.
* **The token is encrypted at rest.** It grants write access to the tracker, which is
  a different class of secret from a webhook URL, so it goes through
  `EncryptionService` like an SSH key rather than sitting in the settings table in
  clear.
"""
import logging
from typing import Any, Dict, List, NamedTuple, Optional

import httpx

from zanshin.models.issue import Issue
from zanshin.services.encryption_service import EncryptionService
from zanshin.services.settings_service import SettingsService
from zanshin.services.url_guard import UnsafeUrlError, validate_outbound_url

logger = logging.getLogger(__name__)

PROVIDER_NONE = "none"
PROVIDER_GITLAB = "gitlab"
PROVIDER_JIRA = "jira"
VALID_PROVIDERS = (PROVIDER_NONE, PROVIDER_GITLAB, PROVIDER_JIRA)

SETTING_KEY_PROVIDER = "ticket_provider"
SETTING_KEY_BASE_URL = "ticket_base_url"
SETTING_KEY_PROJECT = "ticket_project"
SETTING_KEY_TOKEN = "ticket_token"
# Jira needs the account e-mail alongside the API token for basic auth; GitLab does
# not use it.
SETTING_KEY_USER = "ticket_user"
SETTING_KEY_ISSUE_TYPE = "ticket_issue_type"
SETTING_KEY_LABELS = "ticket_labels"
# Self-hosted GitLab and Jira are routinely on a private network, so unlike the
# notification webhook this defaults to *allowing* it — with the setting still there
# to forbid it for a deployment that only uses a hosted tracker.
SETTING_KEY_ALLOW_PRIVATE = "ticket_allow_private_url"

TOKEN_CONTEXT = "setting:ticket_token"
DEFAULT_JIRA_ISSUE_TYPE = "Bug"
DEFAULT_LABELS = "zanshin,security"
HTTP_TIMEOUT_SECONDS = 15.0

# Ceiling per sweep. A first run against a mature backlog would otherwise open several
# hundred tickets in one burst, which is both a rate-limit problem and a social one.
MAX_TICKETS_PER_SWEEP = 20


class Ticket(NamedTuple):
    reference: str
    url: str


class TicketService:
    def __init__(
        self,
        settings_service: SettingsService,
        encryption_service: Optional[EncryptionService] = None,
        http_post=httpx.post,
    ):
        self.settings_service = settings_service
        self.encryption_service = encryption_service
        self._http_post = http_post

    # --- Configuration ---

    def provider(self) -> str:
        value = (self.settings_service.get_setting(SETTING_KEY_PROVIDER, PROVIDER_NONE) or "").strip().lower()
        return value if value in VALID_PROVIDERS else PROVIDER_NONE

    def is_enabled(self) -> bool:
        return (
            self.provider() != PROVIDER_NONE
            and bool(self.base_url())
            and bool(self.project())
            and bool(self.token())
        )

    def base_url(self) -> str:
        return (self.settings_service.get_setting(SETTING_KEY_BASE_URL, "") or "").strip().rstrip("/")

    def project(self) -> str:
        return (self.settings_service.get_setting(SETTING_KEY_PROJECT, "") or "").strip()

    def user(self) -> str:
        return (self.settings_service.get_setting(SETTING_KEY_USER, "") or "").strip()

    def issue_type(self) -> str:
        return (
            self.settings_service.get_setting(SETTING_KEY_ISSUE_TYPE, DEFAULT_JIRA_ISSUE_TYPE)
            or DEFAULT_JIRA_ISSUE_TYPE
        ).strip()

    def labels(self) -> List[str]:
        raw = self.settings_service.get_setting(SETTING_KEY_LABELS, DEFAULT_LABELS) or ""
        return [label.strip() for label in raw.split(",") if label.strip()]

    def allow_private_url(self) -> bool:
        return self.settings_service.get_setting(SETTING_KEY_ALLOW_PRIVATE, "true") == "true"

    def token(self) -> str:
        """The decrypted token, or an empty string.

        Never raises: a token that cannot be decrypted — a rotated `ENCRYPTION_KEY`,
        say — must disable ticket creation, not break the scheduler tick that calls
        this.
        """
        stored = (self.settings_service.get_setting(SETTING_KEY_TOKEN, "") or "").strip()
        if not stored or not self.encryption_service:
            return stored
        try:
            return self.encryption_service.decrypt(stored, context=TOKEN_CONTEXT)
        except Exception:
            logger.error("Ticket token could not be decrypted — ticket creation disabled")
            return ""

    def set_token(self, raw_token: str) -> None:
        """Store the token encrypted, bound to its own setting key."""
        raw_token = (raw_token or "").strip()
        if not raw_token:
            self.settings_service.update_setting(SETTING_KEY_TOKEN, "")
            return
        if not self.encryption_service:
            raise RuntimeError("Le service de chiffrement est requis pour enregistrer un jeton.")
        encrypted = self.encryption_service.encrypt(raw_token, context=TOKEN_CONTEXT)
        self.settings_service.update_setting(SETTING_KEY_TOKEN, encrypted)

    def set_base_url(self, url: str) -> None:
        """Validated at save time, and again before every request."""
        self.settings_service.update_setting(
            SETTING_KEY_BASE_URL, self._validated_base_url(url)
        )

    def _validated_base_url(self, url: str) -> str:
        return validate_outbound_url(
            url, allow_private=self.allow_private_url(), label="URL du gestionnaire de tickets"
        ).rstrip("/")

    # --- Creating ---

    def create_for_issue(self, issue: Issue, target_name: str) -> Optional[Ticket]:
        """Open one ticket. Returns `None` on any failure, having logged it.

        Never raises: this runs from the scheduler tick, and an unreachable tracker
        must not stop the retention pass or the triage expiry that share it.
        """
        if not self.is_enabled():
            return None
        try:
            base_url = self._validated_base_url(self.base_url())
        except UnsafeUrlError as e:
            logger.error("Ticket not created: %s", e)
            return None

        provider = self.provider()
        title = build_title(issue, target_name)
        body = build_body(issue, target_name)
        try:
            if provider == PROVIDER_GITLAB:
                return self._create_gitlab(base_url, title, body)
            return self._create_jira(base_url, title, body)
        except Exception:
            logger.exception(
                "Ticket creation failed for issue %s (non-fatal, will be retried)", issue.id
            )
            return None

    def _create_gitlab(self, base_url: str, title: str, body: str) -> Optional[Ticket]:
        # The project id must be URL-encoded when it is a path ("group/project"),
        # which is how most people have it to hand.
        from urllib.parse import quote

        url = f"{base_url}/api/v4/projects/{quote(self.project(), safe='')}/issues"
        response = self._http_post(
            url,
            headers={"PRIVATE-TOKEN": self.token()},
            json={"title": title, "description": body, "labels": ",".join(self.labels())},
            timeout=HTTP_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = response.json()
        reference = f"#{payload.get('iid')}"
        return Ticket(reference=reference, url=payload.get("web_url") or "")

    def _create_jira(self, base_url: str, title: str, body: str) -> Optional[Ticket]:
        url = f"{base_url}/rest/api/3/issue"
        fields: Dict[str, Any] = {
            "project": {"key": self.project()},
            "summary": title,
            "issuetype": {"name": self.issue_type()},
            # Atlassian Document Format: Jira Cloud's v3 API refuses plain strings
            # for `description`.
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {"type": "paragraph", "content": [{"type": "text", "text": line}]}
                    for line in body.split("\n")
                    if line.strip()
                ],
            },
        }
        if self.labels():
            fields["labels"] = self.labels()

        response = self._http_post(
            url,
            auth=(self.user(), self.token()) if self.user() else None,
            headers={"Accept": "application/json"},
            json={"fields": fields},
            timeout=HTTP_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = response.json()
        key = payload.get("key") or ""
        return Ticket(reference=key, url=f"{base_url}/browse/{key}" if key else "")


def build_title(issue: Issue, target_name: str) -> str:
    """Short enough for a tracker list, specific enough to be searchable."""
    subject = issue.identifier or issue.type
    package = f" — {issue.package_name}" if issue.package_name else ""
    severity = (issue.severity or "unknown").upper()
    return f"[Zanshin][{severity}] {subject}{package} ({target_name})"


def build_body(issue: Issue, target_name: str) -> str:
    """What the ticket says, written for whoever picks it up cold.

    The fixed version comes first among the details, because it is the difference
    between a ticket somebody can close today and a ticket that gets carried between
    three sprints.
    """
    lines = [
        f"Détecté par Zanshin sur **{target_name}**.",
        "",
        f"- Type : {issue.type}",
        f"- Identifiant : {issue.identifier or '—'}",
        f"- Sévérité : {(issue.severity or 'unknown')}",
    ]
    if issue.fix_versions:
        lines.append(f"- **Corrigé dans : {issue.fix_versions}**")
    elif issue.fix_state in ("not-fixed", "wont-fix"):
        lines.append("- Aucun correctif publié à ce jour")
    if issue.package_name:
        version = f" {issue.package_version}" if issue.package_version else ""
        lines.append(f"- Composant : {issue.package_name}{version}")
    if issue.is_direct_dependency is not None:
        lines.append(
            "- Dépendance : "
            + ("directe (déclarée par le projet)" if issue.is_direct_dependency else "transitive")
        )
    if issue.file_path:
        location = issue.file_path + (f":{issue.line}" if issue.line else "")
        lines.append(f"- Emplacement : {location}")
    if issue.is_kev:
        lines.append("- ⚠️ Exploitation active connue (catalogue CISA KEV)")
    if issue.epss_score is not None:
        lines.append(f"- Probabilité d'exploitation (EPSS) : {issue.epss_score:.1%}")
    if issue.link:
        lines.append(f"- Référence : {issue.link}")
    if issue.description:
        lines += ["", issue.description[:1000]]
    lines += [
        "",
        f"Problème Zanshin #{issue.id} — empreinte `{issue.fingerprint}`.",
        "Ce ticket a été ouvert parce que ce problème ferait échouer un build selon la "
        "politique de gate en vigueur pour cette cible.",
    ]
    return "\n".join(lines)


def sweep(
    db,
    *,
    issue_repository,
    gate_policy_service,
    ticket_service: "TicketService",
    audit_log_service=None,
    limit: int = MAX_TICKETS_PER_SWEEP,
) -> List[Issue]:
    """Open tickets for issues that would fail their target's gate. Returns those done.

    Takes its collaborators as arguments rather than holding them, for the same reason
    `IssueService` does: this runs on the scheduler's session, and a service that
    captured a session would be wrong on the second tick.

    The gate is evaluated **one issue at a time**, deliberately. Evaluating a target's
    whole backlog and ticketing every violation would be the same query, but it would
    also mean an issue's ticket depends on which other issues happen to be open — and
    "why did this one get a ticket and that one not" must have an answer that is about
    the issue itself.
    """
    if not ticket_service.is_enabled():
        return []

    from zanshin.services.policy_gate import evaluate

    created: List[Issue] = []
    for issue in issue_repository.find_actionable_without_ticket(limit=limit):
        # An issue always belongs to a target in practice, but a row without one must
        # fall back to the global policy rather than resolve a scope of
        # `("container", None)` — which would raise and take the whole scheduler tick
        # with it, retention and triage expiry included.
        if issue.repo_id:
            kind, target_id = "repository", issue.repo_id
        elif issue.container_id:
            kind, target_id = "container", issue.container_id
        else:
            kind, target_id = None, None
        resolved = gate_policy_service.resolve(kind, target_id)

        if evaluate([issue], resolved.policy).passed:
            # Below the bar for this target: no ticket, and no marker either — the
            # policy may be tightened tomorrow, and the issue should become a
            # candidate again when it is.
            continue

        ticket = ticket_service.create_for_issue(issue, _target_name(issue))
        if not ticket:
            # Left without a reference on purpose, so the next tick retries it.
            continue

        issue.ticket_ref = ticket.reference
        issue.ticket_url = ticket.url
        db.commit()
        created.append(issue)

        if audit_log_service:
            audit_log_service.record(
                "TICKET_CREATED",
                resource_id=str(issue.id),
                description=(
                    f"Ticket {ticket.reference} ouvert pour "
                    f"{issue.identifier or issue.type} ({resolved.description})"
                ),
            )

    if created:
        logger.info("Opened %d tracker ticket(s)", len(created))
    return created


def _target_name(issue: Issue) -> str:
    if issue.repository is not None:
        return issue.repository.name or issue.repository.url
    if issue.container is not None:
        return issue.container.image_string
    return "cible inconnue"
