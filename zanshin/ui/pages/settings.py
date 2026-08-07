import reflex as rx

from zanshin.ui.state import BaseState
from zanshin.ui.auth import requires_admin
from zanshin.ui.layout import main_layout
from zanshin.container import get_container
from zanshin.services.scanners import (
    SETTING_KEY_SCAN_BACKEND,
    SETTING_KEY_LOCAL_API_URL,
    SETTING_KEY_LOCAL_API_SHARED_DIR,
    SETTING_KEY_IMAGE_SCAN_PLATFORM,
    DEFAULT_LOCAL_API_URL,
    DEFAULT_IMAGE_SCAN_PLATFORM,
)
from zanshin.services.enrichment_service import SETTING_KEY_ENRICHMENT_ENABLED
from zanshin.services.license_compliance_service import SETTING_KEY_LICENSE_BLOCKLIST
from zanshin.services.audit_log_service import AuditOperation
from zanshin.services.url_guard import UnsafeUrlError, validate_outbound_url
from zanshin.services.eol_service import (
    DEFAULT_WARN_DAYS as DEFAULT_EOL_WARN_DAYS,
    SETTING_KEY_EOL_ENABLED,
    SETTING_KEY_EOL_WARN_DAYS,
)
from zanshin.services.policy_gate import DEFAULT_FAIL_ON_SEVERITY, SEVERITY_ORDER
from zanshin.services.sast_service import SETTING_KEY_SAST_ENABLED
from zanshin.services.ticket_service import (
    DEFAULT_JIRA_ISSUE_TYPE,
    DEFAULT_LABELS as DEFAULT_TICKET_LABELS,
    PROVIDER_GITLAB,
    PROVIDER_JIRA,
    PROVIDER_NONE as TICKET_PROVIDER_NONE,
    SETTING_KEY_BASE_URL as SETTING_KEY_TICKET_BASE_URL,
    SETTING_KEY_ISSUE_TYPE as SETTING_KEY_TICKET_ISSUE_TYPE,
    SETTING_KEY_LABELS as SETTING_KEY_TICKET_LABELS,
    SETTING_KEY_PROJECT as SETTING_KEY_TICKET_PROJECT,
    SETTING_KEY_PROVIDER as SETTING_KEY_TICKET_PROVIDER,
    SETTING_KEY_USER as SETTING_KEY_TICKET_USER,
)
from zanshin.services.scan_queue import (
    DEFAULT_MAX_CONCURRENT,
    POOL_THREADS,
    SETTING_KEY_MAX_CONCURRENT,
    max_concurrent as scan_max_concurrent,
)
from zanshin.ui.view_models import GatePolicyRow, to_gate_policy_row

# The select needs a concrete value for "no severity rule at all", which is a
# legitimate policy for a gate that only fails on known-exploited vulnerabilities.
NO_SEVERITY_RULE = "aucune"
from zanshin.services.retention_service import (
    SETTING_KEY_RETENTION_KEEP_PER_TARGET,
    SETTING_KEY_RETENTION_MAX_AGE_DAYS,
    DEFAULT_KEEP_PER_TARGET,
    DEFAULT_MAX_AGE_DAYS,
)
from zanshin.services.notification_service import (
    SETTING_KEY_WEBHOOK_URL,
    SETTING_KEY_MIN_SEVERITY,
    SETTING_KEY_NOTIFY_ON_KEV,
    DEFAULT_MIN_SEVERITY,
)
from zanshin.services.ai_review_service import (
    SETTING_KEY_AI_REVIEW_ENABLED,
    SETTING_KEY_AI_REVIEW_MODEL,
    SETTING_KEY_AI_REVIEW_OLLAMA_URL,
    SETTING_KEY_AI_REVIEW_DEPLOYMENT_MODE,
    DEFAULT_OLLAMA_URL,
    DEFAULT_AI_REVIEW_MODEL,
    DEFAULT_AI_REVIEW_DEPLOYMENT_MODE,
)

SCAN_BACKEND_OPTIONS = [
    {"label": "Docker local (Syft + Grype + gitleaks + checkov)", "value": "docker"},
    {"label": "API locale (service sidecar, sans Docker côté Zanshin)", "value": "local_api"},
    {"label": "Cloud OSV.dev (vulnérabilités uniquement, secrets/SBOM restent locaux)", "value": "osv"},
]

# The architectures Docker Hub's official multi-arch images are actually
# published for. This is a convenience list, not a constraint: the setting
# is a free-form `os/arch` string that syft passes straight to the Docker
# daemon, so a platform missing here can still be stored.
IMAGE_SCAN_PLATFORM_OPTIONS = [
    {"label": "linux/amd64 (x86-64 — défaut)", "value": "linux/amd64"},
    {"label": "linux/arm64 (Apple Silicon, AWS Graviton)", "value": "linux/arm64"},
    {"label": "linux/arm/v7 (32 bits, Raspberry Pi)", "value": "linux/arm/v7"},
    {"label": "linux/ppc64le (IBM Power)", "value": "linux/ppc64le"},
    {"label": "linux/s390x (IBM Z)", "value": "linux/s390x"},
]

NOTIFICATION_SEVERITY_OPTIONS = [
    {"label": "Critique uniquement", "value": "critical"},
    {"label": "Élevée et plus (défaut)", "value": "high"},
    {"label": "Moyenne et plus", "value": "medium"},
    {"label": "Toutes", "value": "unknown"},
]

AI_REVIEW_DEPLOYMENT_MODE_OPTIONS = [
    {"label": "Local (recommandé — installation native d'Ollama)", "value": "local"},
    {"label": "Docker (docker-compose.ollama.yml)", "value": "docker"},
]

class SettingsState(BaseState):
    """Exposes the scan-execution settings introduced in ADR-001
    (`scan_backend`, `enrichment_enabled`) through the UI instead of
    requiring direct edits to the `setting` table."""

    scan_backend: str = "docker"
    image_scan_platform: str = DEFAULT_IMAGE_SCAN_PLATFORM
    enrichment_enabled: bool = True
    license_blocklist_input: str = ""
    local_api_url_input: str = DEFAULT_LOCAL_API_URL
    retention_keep_input: str = str(DEFAULT_KEEP_PER_TARGET)
    retention_max_age_input: str = str(DEFAULT_MAX_AGE_DAYS)
    notification_webhook_url_input: str = ""
    notification_min_severity: str = DEFAULT_MIN_SEVERITY
    notification_always_on_kev: bool = True
    local_api_shared_dir_input: str = ""

    ai_review_enabled: bool = False
    ai_review_model: str = DEFAULT_AI_REVIEW_MODEL
    ai_review_ollama_url_input: str = DEFAULT_OLLAMA_URL
    ai_review_available_models: list[str] = [DEFAULT_AI_REVIEW_MODEL]
    ai_review_models_loading: bool = False
    ai_review_deployment_mode: str = DEFAULT_AI_REVIEW_DEPLOYMENT_MODE

    # End-of-life detection
    eol_enabled: bool = True
    sast_enabled: bool = False
    eol_warn_days_input: str = str(DEFAULT_EOL_WARN_DAYS)

    # Gate policy (global scope; per-target overrides are listed below it)
    gate_fail_on_severity: str = DEFAULT_FAIL_ON_SEVERITY
    gate_fail_on_kev: bool = True
    gate_fixable_only: bool = False
    gate_include_triaged: bool = False
    gate_include_ai_review: bool = False
    gate_note_input: str = ""
    gate_policy_rows: list[GatePolicyRow] = []
    gate_policy_version: int = 0

    # Tracker tickets
    ticket_provider: str = TICKET_PROVIDER_NONE
    ticket_base_url_input: str = ""
    ticket_project_input: str = ""
    ticket_user_input: str = ""
    ticket_labels_input: str = DEFAULT_TICKET_LABELS
    ticket_issue_type_input: str = DEFAULT_JIRA_ISSUE_TYPE
    ticket_token_input: str = ""
    ticket_token_present: bool = False

    # Notification outbox, so a stuck queue is visible without reading the table
    outbox_pending: int = 0
    outbox_failed: int = 0

    # Scan queue
    scan_max_concurrent_input: str = str(DEFAULT_MAX_CONCURRENT)
    scan_queued: int = 0
    scan_running: int = 0

    @requires_admin
    def load_settings(self):
        self.set_current_page("Paramètres")
        container = get_container()
        try:
            self._load_eol(container)
            self._load_gate_policy(container)
            self._load_ticket_config(container)
            self._load_outbox_counts(container)
            self._load_scan_queue(container)
            self.scan_backend = container.settings_service.get_setting(SETTING_KEY_SCAN_BACKEND, "docker")
            self.image_scan_platform = container.settings_service.get_setting(
                SETTING_KEY_IMAGE_SCAN_PLATFORM, DEFAULT_IMAGE_SCAN_PLATFORM
            )
            self.enrichment_enabled = container.settings_service.get_setting(
                SETTING_KEY_ENRICHMENT_ENABLED, "true"
            ) == "true"
            self.license_blocklist_input = container.settings_service.get_setting(
                SETTING_KEY_LICENSE_BLOCKLIST, ""
            )
            self.local_api_url_input = container.settings_service.get_setting(
                SETTING_KEY_LOCAL_API_URL, DEFAULT_LOCAL_API_URL
            )
            self.local_api_shared_dir_input = container.settings_service.get_setting(
                SETTING_KEY_LOCAL_API_SHARED_DIR, ""
            )
            self.ai_review_enabled = container.ai_review_service.is_enabled()
            self.ai_review_model = container.ai_review_service.get_selected_model()
            self.ai_review_ollama_url_input = container.ai_review_service.get_ollama_url()
            self.ai_review_available_models = container.ai_review_service.list_available_models()
            self.ai_review_deployment_mode = container.ai_review_service.get_deployment_mode()
            self.retention_keep_input = str(container.retention_service.keep_per_target())
            self.retention_max_age_input = str(container.retention_service.max_age_days())
            self.notification_webhook_url_input = container.notification_service.webhook_url()
            self.notification_min_severity = container.notification_service.min_severity()
            self.notification_always_on_kev = container.notification_service.always_on_kev()
        except Exception as e:
            yield self.trigger_toast(f"Erreur de chargement : {str(e)}", is_error=True)
        finally:
            container.db.close()

    def _load_outbox_counts(self, container) -> None:
        from zanshin.models.outbox_message import STATUS_FAILED, STATUS_PENDING

        tally = container.outbox_repository.count_by_status()
        self.outbox_pending = tally.get(STATUS_PENDING, 0)
        self.outbox_failed = tally.get(STATUS_FAILED, 0)

    def _load_scan_queue(self, container) -> None:
        self.scan_max_concurrent_input = str(scan_max_concurrent(container.settings_service))
        counts = container.scan_repository.count_by_queue_state()
        self.scan_queued = counts.get("queued", 0)
        self.scan_running = counts.get("running", 0)

    def set_scan_max_concurrent_input(self, value: str):
        self.scan_max_concurrent_input = value

    @requires_admin
    def save_scan_max_concurrent(self):
        """Change how many scans run at once, without a restart.

        This used to be `ZANSHIN_SCAN_WORKERS`, read at import: the only way to change
        it was to restart the application, and the number sized a thread pool that also
        *was* the queue. The queue is now in the database and this is the limit applied
        when it claims work.
        """
        container = get_container()
        try:
            value = int(self.scan_max_concurrent_input.strip())
            if value < 1:
                raise ValueError("Au moins un scan doit pouvoir tourner.")
            if value > POOL_THREADS:
                raise ValueError(
                    f"Maximum {POOL_THREADS} (taille du pool de threads, "
                    "ZANSHIN_SCAN_POOL_THREADS)."
                )
            container.settings_service.update_setting(
                SETTING_KEY_MAX_CONCURRENT, str(value)
            )
            container.audit_log_service.record(
                AuditOperation.SETTING_UPDATED,
                resource_id=SETTING_KEY_MAX_CONCURRENT,
                description=f"Scans simultanés maximum : {value}",
                user_id=self.username,
            )
            self._load_scan_queue(container)
            yield self.trigger_toast(f"{value} scan(s) simultané(s) au maximum")
        except ValueError as e:
            yield self.trigger_toast(str(e), is_error=True)
        finally:
            container.db.close()

    def _load_eol(self, container) -> None:
        self.eol_enabled = container.eol_service.is_enabled()
        self.sast_enabled = container.sast_service.is_enabled()
        self.eol_warn_days_input = str(container.eol_service.warn_days())

    def _load_gate_policy(self, container) -> None:
        """The global policy into the form, and every configured scope into the list."""
        resolved = container.gate_policy_service.resolve()
        self.gate_fail_on_severity = resolved.policy.fail_on_severity or NO_SEVERITY_RULE
        self.gate_fail_on_kev = resolved.policy.fail_on_kev
        self.gate_fixable_only = resolved.policy.fixable_only
        self.gate_include_triaged = resolved.policy.include_triaged
        self.gate_include_ai_review = resolved.policy.include_ai_review
        self.gate_policy_version = resolved.version or 0
        self.gate_note_input = ""
        self.gate_policy_rows = [
            to_gate_policy_row(policy, self._scope_name(container, policy))
            for policy in container.gate_policy_service.active_policies()
        ]

    @staticmethod
    def _scope_name(container, policy) -> str:
        """A target's real name rather than `repository:7`, since that is what an
        operator recognises when checking which rules apply where."""
        if policy.is_global:
            return "Toutes les cibles"
        if policy.target_kind == "repository":
            repo = container.repository_repository.find_by_id(policy.target_id)
            return (repo.name or repo.url) if repo else f"dépôt {policy.target_id} (supprimé)"
        image = container.container_repository.find_by_id(policy.target_id)
        return image.image_string if image else f"conteneur {policy.target_id} (supprimé)"

    def _load_ticket_config(self, container) -> None:
        service = container.ticket_service
        self.ticket_provider = service.provider()
        self.ticket_base_url_input = service.base_url()
        self.ticket_project_input = service.project()
        self.ticket_user_input = service.user()
        self.ticket_labels_input = ",".join(service.labels())
        self.ticket_issue_type_input = service.issue_type()
        # Never echoed back into the form — only whether one is stored.
        self.ticket_token_present = bool(service.token())
        self.ticket_token_input = ""

    # --- End-of-life detection ---

    @requires_admin
    def set_sast_enabled(self, value: bool):
        container = get_container()
        try:
            container.sast_service.set_enabled(value)
            container.audit_log_service.record(
                AuditOperation.SETTING_UPDATED,
                resource_id=SETTING_KEY_SAST_ENABLED,
                description=f"Analyse du code source (Semgrep) {'activée' if value else 'désactivée'}",
                user_id=self.username,
            )
            self.sast_enabled = value
            yield self.trigger_toast("Analyse du code source mise à jour")
        except Exception as e:
            yield self.trigger_toast(f"Erreur d'enregistrement : {str(e)}", is_error=True)
        finally:
            container.db.close()

    @requires_admin
    def set_eol_enabled(self, value: bool):
        container = get_container()
        try:
            self.eol_enabled = value
            container.settings_service.update_setting(
                SETTING_KEY_EOL_ENABLED, "true" if value else "false"
            )
            container.audit_log_service.record(
                AuditOperation.SETTING_UPDATED,
                resource_id=SETTING_KEY_EOL_ENABLED,
                description=f"Détection de fin de vie {'activée' if value else 'désactivée'}",
                user_id=self.username,
            )
            yield self.trigger_toast(
                f"Détection de fin de vie {'activée' if value else 'désactivée'}"
            )
        finally:
            container.db.close()

    def set_eol_warn_days_input(self, value: str):
        self.eol_warn_days_input = value

    @requires_admin
    def save_eol_config(self):
        container = get_container()
        try:
            days = int(self.eol_warn_days_input.strip() or DEFAULT_EOL_WARN_DAYS)
            if days < 0:
                raise ValueError("Le délai d'alerte ne peut pas être négatif.")
            container.settings_service.update_setting(SETTING_KEY_EOL_WARN_DAYS, str(days))
            container.audit_log_service.record(
                AuditOperation.SETTING_UPDATED,
                resource_id=SETTING_KEY_EOL_WARN_DAYS,
                description=f"Fenêtre d'alerte de fin de vie : {days} jour(s)",
                user_id=self.username,
            )
            yield self.trigger_toast(f"Alerte {days} jours avant la fin de vie")
        except ValueError as e:
            yield self.trigger_toast(str(e), is_error=True)
        finally:
            container.db.close()

    # --- Gate policy ---

    def set_gate_fail_on_severity(self, value: str):
        self.gate_fail_on_severity = value

    def set_gate_fail_on_kev(self, value: bool):
        self.gate_fail_on_kev = value

    def set_gate_fixable_only(self, value: bool):
        self.gate_fixable_only = value

    def set_gate_include_triaged(self, value: bool):
        self.gate_include_triaged = value

    def set_gate_include_ai_review(self, value: bool):
        self.gate_include_ai_review = value

    def set_gate_note_input(self, value: str):
        self.gate_note_input = value

    @requires_admin
    def save_gate_policy(self):
        """Store a new version of the global policy.

        Not an update: every change is a version, so "which policy failed that build
        in March" has an answer and the author of the decision is recorded.
        """
        container = get_container()
        try:
            severity = (
                None if self.gate_fail_on_severity == NO_SEVERITY_RULE
                else self.gate_fail_on_severity
            )
            policy = container.gate_policy_service.save_policy(
                fail_on_severity=severity,
                fail_on_kev=self.gate_fail_on_kev,
                fixable_only=self.gate_fixable_only,
                include_triaged=self.gate_include_triaged,
                include_ai_review=self.gate_include_ai_review,
                note=self.gate_note_input,
                actor=self.username,
            )
            container.audit_log_service.record(
                AuditOperation.GATE_POLICY_UPDATED,
                resource_id=policy.scope_label,
                description=(
                    f"Politique de gate globale v{policy.version} : seuil "
                    f"{severity or 'aucun'}, KEV {'oui' if policy.fail_on_kev else 'non'}"
                    + (f" — {policy.note}" if policy.note else "")
                ),
                user_id=self.username,
            )
            self._load_gate_policy(container)
            yield self.trigger_toast(f"Politique de gate enregistrée (v{policy.version})")
        except ValueError as e:
            yield self.trigger_toast(str(e), is_error=True)
        except Exception as e:
            yield self.trigger_toast(f"Erreur d'enregistrement : {str(e)}", is_error=True)
        finally:
            container.db.close()

    @requires_admin
    def delete_gate_policy(self, target_kind: str, target_id: int):
        """Drop a per-target override so it inherits the global policy again."""
        container = get_container()
        try:
            container.gate_policy_service.delete_target_policy(target_kind, target_id)
            container.audit_log_service.record(
                AuditOperation.GATE_POLICY_UPDATED,
                resource_id=f"{target_kind}:{target_id}",
                description="Politique de cible supprimée (retour à la politique globale)",
                user_id=self.username,
            )
            self._load_gate_policy(container)
            yield self.trigger_toast("Politique de cible supprimée")
        except ValueError as e:
            yield self.trigger_toast(str(e), is_error=True)
        finally:
            container.db.close()

    # --- Tracker tickets ---

    def set_ticket_provider_input(self, value: str):
        self.ticket_provider = value

    def set_ticket_base_url_input(self, value: str):
        self.ticket_base_url_input = value

    def set_ticket_project_input(self, value: str):
        self.ticket_project_input = value

    def set_ticket_user_input(self, value: str):
        self.ticket_user_input = value

    def set_ticket_labels_input(self, value: str):
        self.ticket_labels_input = value

    def set_ticket_issue_type_input(self, value: str):
        self.ticket_issue_type_input = value

    def set_ticket_token_input(self, value: str):
        self.ticket_token_input = value

    @requires_admin
    def save_ticket_config(self):
        container = get_container()
        try:
            service = container.ticket_service
            container.settings_service.update_setting(
                SETTING_KEY_TICKET_PROVIDER, self.ticket_provider
            )
            if self.ticket_base_url_input.strip():
                # Validated here and again before every request, for the same reason
                # as the notification webhook: a setting can predate the guard.
                service.set_base_url(self.ticket_base_url_input)
            else:
                container.settings_service.update_setting(SETTING_KEY_TICKET_BASE_URL, "")
            container.settings_service.update_setting(
                SETTING_KEY_TICKET_PROJECT, self.ticket_project_input.strip()
            )
            container.settings_service.update_setting(
                SETTING_KEY_TICKET_USER, self.ticket_user_input.strip()
            )
            container.settings_service.update_setting(
                SETTING_KEY_TICKET_LABELS, self.ticket_labels_input.strip()
            )
            container.settings_service.update_setting(
                SETTING_KEY_TICKET_ISSUE_TYPE, self.ticket_issue_type_input.strip()
            )
            # An empty field leaves the stored token alone: the form never shows it,
            # so blanking it out on every save would silently disable ticketing the
            # first time somebody changed the project name.
            if self.ticket_token_input.strip():
                service.set_token(self.ticket_token_input)

            container.audit_log_service.record(
                AuditOperation.SETTING_UPDATED,
                resource_id=SETTING_KEY_TICKET_PROVIDER,
                # The token is never described, and neither is the URL: both are
                # credentials in this context.
                description=(
                    f"Gestionnaire de tickets : {self.ticket_provider}"
                    + (" (jeton mis à jour)" if self.ticket_token_input.strip() else "")
                ),
                user_id=self.username,
            )
            self._load_ticket_config(container)
            self._load_outbox_counts(container)
            self._load_scan_queue(container)
            yield self.trigger_toast("Configuration des tickets enregistrée")
        except UnsafeUrlError as e:
            yield self.trigger_toast(str(e), is_error=True)
        except Exception as e:
            yield self.trigger_toast(f"Erreur d'enregistrement : {str(e)}", is_error=True)
        finally:
            container.db.close()

    def set_local_api_url_input(self, value: str):
        self.local_api_url_input = value

    def set_local_api_shared_dir_input(self, value: str):
        self.local_api_shared_dir_input = value

    @requires_admin
    def save_local_api_config(self):
        container = get_container()
        try:
            # Private and loopback are expected here (the sidecar shares the host),
            # link-local is not — see zanshin/services/url_guard.py.
            validate_outbound_url(
                self.local_api_url_input, allow_private=True, label="URL du service local"
            )
            container.settings_service.update_setting(
                SETTING_KEY_LOCAL_API_URL, self.local_api_url_input.strip()
            )
            container.settings_service.update_setting(
                SETTING_KEY_LOCAL_API_SHARED_DIR, self.local_api_shared_dir_input.strip()
            )
            container.audit_log_service.record(
                AuditOperation.SETTING_UPDATED,
                resource_id=SETTING_KEY_LOCAL_API_URL,
                description=f"Configuration API locale mise à jour ({self.local_api_url_input.strip()})",
                user_id=self.username,
            )
            yield self.trigger_toast("Configuration de l'API locale mise à jour")
        except Exception as e:
            yield self.trigger_toast(f"Erreur d'enregistrement : {str(e)}", is_error=True)
        finally:
            container.db.close()

    def set_retention_keep_input(self, value: str):
        self.retention_keep_input = value

    def set_retention_max_age_input(self, value: str):
        self.retention_max_age_input = value

    @requires_admin
    def save_retention_config(self):
        container = get_container()
        try:
            # Validated here so a typo becomes a message rather than a silently
            # ignored setting (RetentionService falls back to its default on a
            # non-integer, which would look like the save had worked).
            for label, raw in (
                ("Nombre de scans à conserver", self.retention_keep_input),
                ("Âge maximum", self.retention_max_age_input),
            ):
                if not raw.strip().isdigit():
                    yield self.trigger_toast(
                        f"{label} : entier positif attendu (0 = sans limite).", is_error=True
                    )
                    return

            container.settings_service.update_setting(
                SETTING_KEY_RETENTION_KEEP_PER_TARGET, self.retention_keep_input.strip()
            )
            container.settings_service.update_setting(
                SETTING_KEY_RETENTION_MAX_AGE_DAYS, self.retention_max_age_input.strip()
            )
            container.audit_log_service.record(
                AuditOperation.SETTING_UPDATED,
                resource_id=SETTING_KEY_RETENTION_KEEP_PER_TARGET,
                description=(
                    f"Rétention des données brutes : {self.retention_keep_input.strip()} scans/cible, "
                    f"{self.retention_max_age_input.strip()} jours"
                ),
                user_id=self.username,
            )
            yield self.trigger_toast("Politique de rétention enregistrée")
        except Exception as e:
            yield self.trigger_toast(f"Erreur d'enregistrement : {str(e)}", is_error=True)
        finally:
            container.db.close()

    def set_notification_webhook_url_input(self, value: str):
        self.notification_webhook_url_input = value

    @requires_admin
    def save_notification_config(self):
        container = get_container()
        try:
            url = self.notification_webhook_url_input.strip()
            # A webhook is expected to be a public endpoint; a URL resolving to a
            # private address is far more often an SSRF attempt than an intranet
            # sink (see url_guard, and `notification_allow_private_url` to opt in).
            if url:
                validate_outbound_url(
                    url,
                    allow_private=container.notification_service.allow_private_url(),
                    label="URL de webhook",
                )
            container.settings_service.update_setting(SETTING_KEY_WEBHOOK_URL, url)
            container.settings_service.update_setting(
                SETTING_KEY_MIN_SEVERITY, self.notification_min_severity
            )
            container.settings_service.update_setting(
                SETTING_KEY_NOTIFY_ON_KEV, "true" if self.notification_always_on_kev else "false"
            )
            container.audit_log_service.record(
                AuditOperation.SETTING_UPDATED,
                resource_id=SETTING_KEY_WEBHOOK_URL,
                # The URL itself is not logged: a webhook URL is usually a
                # bearer secret in disguise (Slack, Teams and Discord all embed
                # a token in the path), and the audit log is readable by every
                # admin.
                description=(
                    "Notifications désactivées" if not url
                    else f"Notifications activées (seuil : {self.notification_min_severity})"
                ),
                user_id=self.username,
            )
            yield self.trigger_toast(
                "Notifications enregistrées" if url else "Notifications désactivées"
            )
        except Exception as e:
            yield self.trigger_toast(f"Erreur d'enregistrement : {str(e)}", is_error=True)
        finally:
            container.db.close()

    @requires_admin
    def set_notification_min_severity(self, value: str):
        self.notification_min_severity = value
        return SettingsState.save_notification_config

    @requires_admin
    def set_notification_always_on_kev(self, value: bool):
        self.notification_always_on_kev = value
        return SettingsState.save_notification_config

    def set_license_blocklist_input(self, value: str):
        self.license_blocklist_input = value

    @requires_admin
    def save_license_blocklist(self):
        container = get_container()
        try:
            container.settings_service.update_setting(
                SETTING_KEY_LICENSE_BLOCKLIST, self.license_blocklist_input.strip()
            )
            container.audit_log_service.record(
                AuditOperation.SETTING_UPDATED,
                resource_id=SETTING_KEY_LICENSE_BLOCKLIST,
                description=f"Liste des licences bloquées mise à jour ('{self.license_blocklist_input.strip()}')",
                user_id=self.username,
            )
            yield self.trigger_toast("Liste des licences bloquées mise à jour")
        except Exception as e:
            yield self.trigger_toast(f"Erreur d'enregistrement : {str(e)}", is_error=True)
        finally:
            container.db.close()

    @requires_admin
    def set_image_scan_platform(self, value: str):
        container = get_container()
        try:
            container.settings_service.update_setting(SETTING_KEY_IMAGE_SCAN_PLATFORM, value)
            container.audit_log_service.record(
                AuditOperation.SETTING_UPDATED,
                resource_id=SETTING_KEY_IMAGE_SCAN_PLATFORM,
                description=f"Architecture auditée pour les images changée pour '{value}'",
                user_id=self.username,
            )
            self.image_scan_platform = value
            # Existing scans keep the SBOM of whatever platform was set when
            # they ran; the CVE set differs per architecture, so results from
            # before and after this change aren't directly comparable.
            yield self.trigger_toast(
                f"Architecture auditée : {value} — relancez les scans pour appliquer le changement"
            )
        except Exception as e:
            yield self.trigger_toast(f"Erreur d'enregistrement : {str(e)}", is_error=True)
        finally:
            container.db.close()

    @requires_admin
    def set_scan_backend(self, value: str):
        container = get_container()
        try:
            container.settings_service.update_setting(SETTING_KEY_SCAN_BACKEND, value)
            container.audit_log_service.record(
                AuditOperation.SETTING_UPDATED,
                resource_id=SETTING_KEY_SCAN_BACKEND,
                description=f"Backend de scan changé pour '{value}'",
                user_id=self.username,
            )
            self.scan_backend = value
            yield self.trigger_toast("Backend de scan mis à jour")
        except Exception as e:
            yield self.trigger_toast(f"Erreur d'enregistrement : {str(e)}", is_error=True)
        finally:
            container.db.close()

    @requires_admin
    def set_enrichment_enabled(self, value: bool):
        container = get_container()
        try:
            container.settings_service.update_setting(
                SETTING_KEY_ENRICHMENT_ENABLED, "true" if value else "false"
            )
            container.audit_log_service.record(
                AuditOperation.SETTING_UPDATED,
                resource_id=SETTING_KEY_ENRICHMENT_ENABLED,
                description=f"Enrichissement EPSS/KEV {'activé' if value else 'désactivé'}",
                user_id=self.username,
            )
            self.enrichment_enabled = value
            yield self.trigger_toast("Enrichissement EPSS/KEV mis à jour")
        except Exception as e:
            yield self.trigger_toast(f"Erreur d'enregistrement : {str(e)}", is_error=True)
        finally:
            container.db.close()

    @requires_admin
    def set_ai_review_enabled(self, value: bool):
        container = get_container()
        try:
            container.ai_review_service.set_enabled(value)
            container.audit_log_service.record(
                AuditOperation.SETTING_UPDATED,
                resource_id=SETTING_KEY_AI_REVIEW_ENABLED,
                description=f"Revue de code par IA {'activée' if value else 'désactivée'}",
                user_id=self.username,
            )
            self.ai_review_enabled = value
            yield self.trigger_toast("Revue de code par IA mise à jour")
        except Exception as e:
            yield self.trigger_toast(f"Erreur d'enregistrement : {str(e)}", is_error=True)
        finally:
            container.db.close()

    @requires_admin
    def set_ai_review_deployment_mode(self, value: str):
        container = get_container()
        try:
            container.ai_review_service.set_deployment_mode(value)
            container.audit_log_service.record(
                AuditOperation.SETTING_UPDATED,
                resource_id=SETTING_KEY_AI_REVIEW_DEPLOYMENT_MODE,
                description=f"Mode de déploiement Ollama changé pour '{value}'",
                user_id=self.username,
            )
            self.ai_review_deployment_mode = value
            yield self.trigger_toast("Mode de déploiement Ollama mis à jour")
        except Exception as e:
            yield self.trigger_toast(f"Erreur d'enregistrement : {str(e)}", is_error=True)
        finally:
            container.db.close()

    def set_ai_review_ollama_url_input(self, value: str):
        self.ai_review_ollama_url_input = value

    @requires_admin
    def save_ai_review_ollama_url(self):
        container = get_container()
        try:
            container.ai_review_service.set_ollama_url(self.ai_review_ollama_url_input)
            container.audit_log_service.record(
                AuditOperation.SETTING_UPDATED,
                resource_id=SETTING_KEY_AI_REVIEW_OLLAMA_URL,
                description=f"URL du service Ollama mise à jour ({self.ai_review_ollama_url_input.strip()})",
                user_id=self.username,
            )
            yield self.trigger_toast("URL du service Ollama mise à jour")
        except Exception as e:
            yield self.trigger_toast(f"Erreur d'enregistrement : {str(e)}", is_error=True)
        finally:
            container.db.close()

    @requires_admin
    def refresh_ai_review_models(self):
        """Re-queries Ollama's `/api/tags` live — lets the dropdown pick up
        models pulled after the page was first loaded, without a full
        reload."""
        self.ai_review_models_loading = True
        yield
        container = get_container()
        try:
            self.ai_review_available_models = container.ai_review_service.list_available_models()
            yield self.trigger_toast("Liste des modèles Ollama actualisée")
        except Exception as e:
            yield self.trigger_toast(f"Erreur de rafraîchissement : {str(e)}", is_error=True)
        finally:
            self.ai_review_models_loading = False
            container.db.close()

    @requires_admin
    def set_ai_review_model(self, value: str):
        container = get_container()
        try:
            container.ai_review_service.set_selected_model(value)
            container.audit_log_service.record(
                AuditOperation.SETTING_UPDATED,
                resource_id=SETTING_KEY_AI_REVIEW_MODEL,
                description=f"Modèle de revue de code IA changé pour '{value}'",
                user_id=self.username,
            )
            self.ai_review_model = value
            yield self.trigger_toast("Modèle de revue de code IA mis à jour")
        except Exception as e:
            yield self.trigger_toast(f"Erreur d'enregistrement : {str(e)}", is_error=True)
        finally:
            container.db.close()

def switch_row(label: str, checked, on_change, hint: str = "") -> rx.Component:
    """One rule of the gate policy: a switch, its wording, and — where the choice has a
    consequence worth stating — why it is not the obvious default."""
    return rx.vstack(
        rx.hstack(
            rx.switch(checked=checked, on_change=on_change, size="1"),
            rx.text(label, size="2"),
            spacing="3",
            align="center",
        ),
        rx.cond(
            hint != "",
            rx.text(hint, size="1", color="var(--slate-10)", class_name="ml-9"),
        ),
        spacing="0",
        width="100%",
        align="start",
    )


def gate_policy_row(row: rx.Var) -> rx.Component:
    return rx.table.row(
        rx.table.cell(
            rx.vstack(
                rx.text(row.scope, size="2", weight="medium"),
                rx.cond(
                    row.is_global,
                    rx.text("politique par défaut", size="1", color="var(--slate-10)"),
                ),
                spacing="0",
            )
        ),
        rx.table.cell(
            rx.vstack(
                rx.text(row.rules, size="2"),
                rx.cond(row.note != "", rx.text(row.note, size="1", color="var(--slate-10)")),
                spacing="0",
            )
        ),
        rx.table.cell(rx.badge("v", row.version, variant="soft")),
        rx.table.cell(
            rx.vstack(
                rx.text(row.author, size="2"),
                rx.text(row.changed_at, size="1", color="var(--slate-10)"),
                spacing="0",
            )
        ),
        rx.table.cell(
            rx.cond(
                row.is_global,
                rx.text("—", size="2", color="var(--slate-10)"),
                rx.button(
                    rx.icon(tag="trash-2", size=14),
                    size="1",
                    variant="soft",
                    color_scheme="red",
                    on_click=lambda: SettingsState.delete_gate_policy(
                        row.target_kind, row.target_id
                    ),
                ),
            )
        ),
    )


def settings_page() -> rx.Component:
    """Scan-execution settings view: choose the ScannerEngine backend and
    toggle EPSS/CISA-KEV enrichment (see ADR-001)."""
    content = rx.vstack(
        rx.text(
            "Configure le moteur d'analyse et l'enrichissement des vulnérabilités utilisés par les prochains scans.",
            size="2", color="var(--slate-10)"
        ),

        # Scan backend
        rx.vstack(
            rx.heading("Backend de scan", size="3", weight="bold"),
            rx.text(
                "Détermine où s'exécutent la génération de SBOM et l'analyse des vulnérabilités/secrets. "
                "Ne s'applique qu'aux scans lancés après ce changement.",
                size="2", color="var(--slate-10)", class_name="mb-2"
            ),
            rx.select.root(
                rx.select.trigger(placeholder="Choisir un backend..."),
                rx.select.content(
                    rx.select.group(
                        rx.foreach(
                            SCAN_BACKEND_OPTIONS,
                            lambda opt: rx.select.item(opt["label"], value=opt["value"])
                        )
                    )
                ),
                value=SettingsState.scan_backend,
                on_change=SettingsState.set_scan_backend,
                width="100%"
            ),
            rx.cond(
                SettingsState.scan_backend == "osv",
                rx.callout(
                    "Ce mode envoie les identifiants de paquets (purl) à l'API publique OSV.dev pour "
                    "le matching de vulnérabilités. Le SBOM et le scan de secrets restent locaux.",
                    icon="info", color_scheme="blue", size="1", class_name="mt-2"
                ),
                rx.cond(
                    SettingsState.scan_backend == "local_api",
                    rx.vstack(
                        rx.callout(
                            "Nécessite le service sidecar scan-api/ déployé sur la même machine que Zanshin, "
                            "avec un volume partagé — voir scan-api/README.md. Zanshin n'a alors plus besoin "
                            "d'accès au socket Docker.",
                            icon="server", color_scheme="amber", size="1", class_name="mt-2"
                        ),
                        rx.hstack(
                            rx.vstack(
                                rx.text("URL du service", size="1", weight="medium"),
                                rx.input(
                                    placeholder=DEFAULT_LOCAL_API_URL,
                                    value=SettingsState.local_api_url_input,
                                    on_change=SettingsState.set_local_api_url_input,
                                    class_name="w-full"
                                ),
                                width="50%", spacing="1"
                            ),
                            rx.vstack(
                                rx.text("Répertoire partagé", size="1", weight="medium"),
                                rx.input(
                                    placeholder="Ex: /shared/zanshin-scans",
                                    value=SettingsState.local_api_shared_dir_input,
                                    on_change=SettingsState.set_local_api_shared_dir_input,
                                    class_name="w-full"
                                ),
                                width="50%", spacing="1"
                            ),
                            spacing="3",
                            width="100%",
                            class_name="mt-2"
                        ),
                        rx.button(
                            "Enregistrer la configuration API locale",
                            on_click=SettingsState.save_local_api_config,
                            color_scheme="cyan",
                            size="2",
                            class_name="mt-2"
                        ),
                        width="100%", spacing="1"
                    ),
                    rx.callout(
                        "Aucune donnée ne quitte cette machine : SBOM, vulnérabilités et secrets sont analysés "
                        "localement via des conteneurs Docker éphémères.",
                        icon="shield-check", color_scheme="green", size="1", class_name="mt-2"
                    )
                )
            ),
            width="100%",
            spacing="2",
            class_name="p-6 rounded-xl bg-slate-2 border border-slate-4 shadow-sm mb-6"
        ),

        # Audited image architecture
        rx.vstack(
            rx.heading("Architecture auditée (images de conteneurs)", size="3", weight="bold"),
            rx.text(
                "Une image multi-architecture contient un système de fichiers différent par plateforme, "
                "donc un SBOM et un jeu de CVE différents. Ce réglage fixe la variante analysée, "
                "indépendamment de l'architecture de la machine qui exécute Zanshin. "
                "Ne concerne pas les scans de dépôts Git.",
                size="2", color="var(--slate-10)", class_name="mb-2"
            ),
            rx.select.root(
                rx.select.trigger(placeholder="Choisir une architecture..."),
                rx.select.content(
                    rx.select.group(
                        rx.foreach(
                            IMAGE_SCAN_PLATFORM_OPTIONS,
                            lambda opt: rx.select.item(opt["label"], value=opt["value"])
                        )
                    )
                ),
                value=SettingsState.image_scan_platform,
                on_change=SettingsState.set_image_scan_platform,
                width="100%"
            ),
            rx.cond(
                SettingsState.scan_backend == "local_api",
                rx.callout(
                    "Sans effet avec le backend « API locale » : c'est le service sidecar qui choisit "
                    "la plateforme qu'il analyse.",
                    icon="info", color_scheme="amber", size="1", class_name="mt-2"
                ),
                rx.callout(
                    "Les scans déjà effectués conservent l'architecture en vigueur au moment de leur exécution : "
                    "relancez-les pour comparer sur la même base.",
                    icon="info", color_scheme="blue", size="1", class_name="mt-2"
                ),
            ),
            width="100%",
            spacing="2",
            class_name="p-6 rounded-xl bg-slate-2 border border-slate-4 shadow-sm mb-6"
        ),

        # Scan queue
        rx.vstack(
            rx.hstack(
                rx.heading("File d'attente des scans", size="3", weight="bold"),
                rx.cond(
                    SettingsState.scan_running > 0,
                    rx.badge(SettingsState.scan_running, " en cours", color_scheme="cyan", variant="soft"),
                ),
                rx.cond(
                    SettingsState.scan_queued > 0,
                    rx.badge(SettingsState.scan_queued, " en attente", color_scheme="amber", variant="soft"),
                ),
                spacing="3",
                align="center",
            ),
            rx.text(
                "Les scans sont exécutés dans l'ordre où ils ont été demandés, autant "
                "que la limite ci-dessous l'autorise. La file vit en base : une demande "
                "survit à un redémarrage, et sa place est connue. Chaque scan peut tenir "
                "un conteneur d'analyse ouvert, donc la bonne valeur dépend de la machine.",
                size="2", color="var(--slate-10)", class_name="mb-2"
            ),
            # The number below is this instance's own capacity, i.e. the built-in
            # agent's. Said here because it is the natural place to look for it, and
            # because an operator who wants scans to stop running on this machine
            # needs to know that the switch is on another screen.
            rx.callout(
                rx.hstack(
                    rx.text(
                        "Cette limite est celle de l'agent intégré, c'est-à-dire de "
                        "cette instance. Les agents distants ont chacun la leur.",
                        size="1",
                    ),
                    rx.link("Voir les agents", href="/agents", size="1", weight="medium"),
                    spacing="2",
                    align="center",
                    wrap="wrap",
                ),
                icon="server",
                color_scheme="cyan",
                size="1",
                class_name="mb-2",
            ),
            rx.hstack(
                rx.text("Scans simultanés maximum", size="2", weight="medium"),
                rx.input(
                    value=SettingsState.scan_max_concurrent_input,
                    on_change=SettingsState.set_scan_max_concurrent_input,
                    type="number",
                    width="110px",
                ),
                rx.button(
                    "Enregistrer", on_click=SettingsState.save_scan_max_concurrent,
                    color_scheme="cyan", size="2",
                ),
                spacing="3",
                align="center",
            ),
            width="100%",
            spacing="2",
            class_name="p-6 rounded-xl bg-slate-2 border border-slate-4 shadow-sm mb-6"
        ),

        # Gate policy
        rx.vstack(
            rx.hstack(
                rx.heading("Politique de gate CI", size="3", weight="bold"),
                rx.cond(
                    SettingsState.gate_policy_version > 0,
                    rx.badge("v", SettingsState.gate_policy_version, color_scheme="cyan", variant="soft"),
                ),
                spacing="3",
                align="center",
            ),
            rx.text(
                "Ce qui fait échouer un build. Ces règles arrivaient auparavant dans le corps de "
                "la requête, donc chaque projet décidait lui-même du seuil qu'on lui appliquait. "
                "Une requête peut encore les durcir — jamais les assouplir — et le verdict indique "
                "quelle politique a été appliquée.",
                size="2", color="var(--slate-10)", class_name="mb-2"
            ),
            rx.hstack(
                rx.vstack(
                    rx.text("Échouer à partir de", size="2", weight="medium"),
                    rx.select(
                        [NO_SEVERITY_RULE, *SEVERITY_ORDER],
                        value=SettingsState.gate_fail_on_severity,
                        on_change=SettingsState.set_gate_fail_on_severity,
                        width="180px",
                    ),
                    spacing="1",
                ),
                rx.vstack(
                    rx.text("Motif de ce changement", size="2", weight="medium"),
                    rx.input(
                        placeholder="Facultatif — pourquoi cette version",
                        value=SettingsState.gate_note_input,
                        on_change=SettingsState.set_gate_note_input,
                        width="100%",
                    ),
                    spacing="1",
                    class_name="flex-1",
                ),
                spacing="4",
                width="100%",
                align="end",
            ),
            rx.vstack(
                switch_row(
                    "Échouer sur toute vulnérabilité activement exploitée (CISA KEV)",
                    SettingsState.gate_fail_on_kev,
                    SettingsState.set_gate_fail_on_kev,
                ),
                switch_row(
                    "N'échouer que sur les problèmes ayant un correctif publié",
                    SettingsState.gate_fixable_only,
                    SettingsState.set_gate_fixable_only,
                    hint="Pragmatique, mais tolère silencieusement une faille exploitée sans correctif.",
                ),
                switch_row(
                    "Compter aussi les problèmes déjà triés",
                    SettingsState.gate_include_triaged,
                    SettingsState.set_gate_include_triaged,
                ),
                switch_row(
                    "Laisser la revue IA influencer le verdict",
                    SettingsState.gate_include_ai_review,
                    SettingsState.set_gate_include_ai_review,
                    hint="Le modèle lit le code du dépôt : un dépôt hostile pourrait orienter le verdict.",
                ),
                spacing="2",
                width="100%",
                class_name="mt-3",
            ),
            rx.button(
                "Enregistrer une nouvelle version",
                on_click=SettingsState.save_gate_policy,
                color_scheme="cyan",
                class_name="mt-3",
            ),
            rx.cond(
                SettingsState.gate_policy_rows.length() > 0,
                rx.box(
                    rx.table.root(
                        rx.table.header(
                            rx.table.row(
                                rx.table.column_header_cell("Portée"),
                                rx.table.column_header_cell("Règles"),
                                rx.table.column_header_cell("Version"),
                                rx.table.column_header_cell("Modifiée par"),
                                rx.table.column_header_cell(""),
                            )
                        ),
                        rx.table.body(
                            rx.foreach(SettingsState.gate_policy_rows, gate_policy_row)
                        ),
                        variant="surface",
                        width="100%",
                    ),
                    class_name="w-full overflow-x-auto rounded-lg border border-slate-4 mt-4",
                ),
            ),
            width="100%",
            spacing="2",
            class_name="p-6 rounded-xl bg-slate-2 border border-slate-4 shadow-sm mb-6"
        ),

        # Semgrep source-code analysis
        rx.vstack(
            rx.heading("Analyse du code source (Semgrep)", size="3", weight="bold"),
            rx.text(
                "Cherche dans le code lui-même ce qu'aucun autre scanner ne voit : une "
                "requête SQL concaténée, une commande passée au shell, un certificat TLS "
                "non vérifié. Tourne dans un conteneur sans accès réseau, avec des règles "
                "embarquées — rien du code ne quitte la machine.",
                size="2", color="var(--slate-10)", class_name="mb-2"
            ),
            rx.text(
                "Deux natures de constats : « Code vulnérable », traité comme toute "
                "vulnérabilité, et « Qualité », qui reste visible dans le backlog mais "
                "n'entre jamais dans le verdict du gate CI — activer cette analyse ne "
                "peut pas faire rougir vos chaînes d'intégration du jour au lendemain.",
                size="2", color="var(--slate-10)", class_name="mb-2"
            ),
            rx.hstack(
                rx.switch(
                    checked=SettingsState.sast_enabled,
                    on_change=SettingsState.set_sast_enabled,
                ),
                rx.text(
                    rx.cond(SettingsState.sast_enabled, "Activé", "Désactivé"),
                    size="2", weight="medium",
                ),
                spacing="3",
                align="center",
            ),
            rx.callout(
                "Zanshin embarque ses propres règles. Les jeux de règles publics de "
                "Semgrep ne sont pas redistribuables : pour élargir la couverture, "
                "installez-les vous-même avec « uv run python scripts/fetch_semgrep_rules.py » "
                "et indiquez le répertoire dans ZANSHIN_SEMGREP_RULES_DIR. Mettre à jour "
                "les règles est alors un déploiement, pas un réglage.",
                icon="info",
                size="1",
                color_scheme="gray",
                class_name="mt-3",
            ),
            width="100%",
            align_items="start",
            class_name="p-6 rounded-xl bg-slate-2 border border-slate-4 shadow-sm mb-6",
        ),

        # End-of-life detection
        rx.vstack(
            rx.heading("Détection de fin de vie", size="3", weight="bold"),
            rx.text(
                "Interroge endoflife.date pour signaler les plateformes et exécutions dont le "
                "support de sécurité est terminé — la distribution d'une image de conteneur en "
                "premier lieu. C'est une classe de risque sans CVE : aucun correctif ne sera publié "
                "pour la prochaine faille, quelle qu'elle soit. Seuls des noms de produits et des "
                "versions sont envoyés.",
                size="2", color="var(--slate-10)", class_name="mb-2"
            ),
            rx.hstack(
                rx.switch(
                    checked=SettingsState.eol_enabled,
                    on_change=SettingsState.set_eol_enabled,
                ),
                rx.text(
                    rx.cond(SettingsState.eol_enabled, "Activé", "Désactivé"),
                    size="2", weight="medium",
                ),
                spacing="3",
                align="center",
            ),
            rx.hstack(
                rx.text("Alerter", size="2"),
                rx.input(
                    value=SettingsState.eol_warn_days_input,
                    on_change=SettingsState.set_eol_warn_days_input,
                    type="number",
                    width="110px",
                ),
                rx.text("jours avant l'échéance", size="2"),
                rx.button(
                    "Enregistrer", on_click=SettingsState.save_eol_config,
                    color_scheme="cyan", size="2",
                ),
                spacing="3",
                align="center",
                class_name="mt-2",
            ),
            width="100%",
            spacing="2",
            class_name="p-6 rounded-xl bg-slate-2 border border-slate-4 shadow-sm mb-6"
        ),

        # Tracker tickets
        rx.vstack(
            rx.heading("Tickets (GitLab / Jira)", size="3", weight="bold"),
            rx.text(
                "Ouvre un ticket pour chaque problème qui ferait échouer un build selon la "
                "politique ci-dessus — un seul seuil, défini une seule fois. Un ticket par problème, "
                "posé une fois pour toute sa vie : sa référence est conservée sur le problème, ce qui "
                "rend l'opération réessayable sans risque de doublon.",
                size="2", color="var(--slate-10)", class_name="mb-2"
            ),
            rx.hstack(
                rx.vstack(
                    rx.text("Fournisseur", size="2", weight="medium"),
                    rx.select(
                        [TICKET_PROVIDER_NONE, PROVIDER_GITLAB, PROVIDER_JIRA],
                        value=SettingsState.ticket_provider,
                        on_change=SettingsState.set_ticket_provider_input,
                        width="160px",
                    ),
                    spacing="1",
                ),
                rx.vstack(
                    rx.text("URL de l'instance", size="2", weight="medium"),
                    rx.input(
                        placeholder="https://gitlab.example.com",
                        value=SettingsState.ticket_base_url_input,
                        on_change=SettingsState.set_ticket_base_url_input,
                        width="100%",
                    ),
                    spacing="1",
                    class_name="flex-1",
                ),
                spacing="4",
                width="100%",
                align="end",
            ),
            rx.hstack(
                rx.vstack(
                    rx.text("Projet", size="2", weight="medium"),
                    rx.input(
                        placeholder="groupe/projet (GitLab) ou SEC (Jira)",
                        value=SettingsState.ticket_project_input,
                        on_change=SettingsState.set_ticket_project_input,
                        width="100%",
                    ),
                    spacing="1",
                    class_name="flex-1",
                ),
                rx.vstack(
                    rx.text("Compte (Jira uniquement)", size="2", weight="medium"),
                    rx.input(
                        placeholder="bot@example.com",
                        value=SettingsState.ticket_user_input,
                        on_change=SettingsState.set_ticket_user_input,
                        width="100%",
                    ),
                    spacing="1",
                    class_name="flex-1",
                ),
                spacing="4",
                width="100%",
                align="end",
                class_name="mt-2",
            ),
            rx.hstack(
                rx.vstack(
                    rx.text("Étiquettes", size="2", weight="medium"),
                    rx.input(
                        value=SettingsState.ticket_labels_input,
                        on_change=SettingsState.set_ticket_labels_input,
                        width="100%",
                    ),
                    spacing="1",
                    class_name="flex-1",
                ),
                rx.vstack(
                    rx.text("Type de ticket (Jira)", size="2", weight="medium"),
                    rx.input(
                        value=SettingsState.ticket_issue_type_input,
                        on_change=SettingsState.set_ticket_issue_type_input,
                        width="100%",
                    ),
                    spacing="1",
                    class_name="flex-1",
                ),
                spacing="4",
                width="100%",
                align="end",
                class_name="mt-2",
            ),
            rx.vstack(
                rx.hstack(
                    rx.text("Jeton d'accès", size="2", weight="medium"),
                    rx.cond(
                        SettingsState.ticket_token_present,
                        rx.badge("enregistré", color_scheme="green", variant="soft", size="1"),
                    ),
                    spacing="2",
                    align="center",
                ),
                rx.input(
                    placeholder="Laisser vide pour conserver le jeton actuel",
                    value=SettingsState.ticket_token_input,
                    on_change=SettingsState.set_ticket_token_input,
                    type="password",
                    width="100%",
                ),
                rx.text(
                    "Chiffré en base (AES-GCM) comme une clé SSH : il donne un droit d'écriture "
                    "sur le gestionnaire de tickets. Il n'est jamais réaffiché.",
                    size="1", color="var(--slate-10)",
                ),
                spacing="1",
                width="100%",
                class_name="mt-2",
            ),
            rx.button(
                "Enregistrer", on_click=SettingsState.save_ticket_config,
                color_scheme="cyan", class_name="mt-3",
            ),
            width="100%",
            spacing="2",
            class_name="p-6 rounded-xl bg-slate-2 border border-slate-4 shadow-sm mb-6"
        ),

        # Enrichment toggle
        rx.vstack(
            rx.heading("Enrichissement EPSS / CISA KEV", size="3", weight="bold"),
            rx.text(
                "Après chaque scan de dépôt, interroge les API publiques et gratuites EPSS (first.org) et "
                "CISA KEV pour prioriser les vulnérabilités par probabilité d'exploitation réelle, plutôt "
                "que par seule sévérité CVSS. Seuls des identifiants CVE sont envoyés. Désactiver pour un "
                "déploiement strictement hors-ligne.",
                size="2", color="var(--slate-10)", class_name="mb-2"
            ),
            rx.hstack(
                rx.switch(
                    checked=SettingsState.enrichment_enabled,
                    on_change=SettingsState.set_enrichment_enabled,
                ),
                rx.text(
                    rx.cond(SettingsState.enrichment_enabled, "Activé", "Désactivé"),
                    size="2", weight="medium"
                ),
                spacing="3",
                align="center"
            ),
            width="100%",
            spacing="2",
            class_name="p-6 rounded-xl bg-slate-2 border border-slate-4 shadow-sm mb-6"
        ),

        # License blocklist
        rx.vstack(
            rx.heading("Conformité des licences", size="3", weight="bold"),
            rx.text(
                "Identifiants SPDX séparés par des virgules (ex: GPL-3.0-only,AGPL-3.0-only). Basé sur les "
                "licences déjà détectées par Syft dans le SBOM — aucun nouvel outil de scan requis. Vide par "
                "défaut : rien n'est signalé tant qu'une liste n'est pas configurée.",
                size="2", color="var(--slate-10)", class_name="mb-2"
            ),
            rx.hstack(
                rx.input(
                    placeholder="Ex: GPL-3.0-only,AGPL-3.0-only",
                    value=SettingsState.license_blocklist_input,
                    on_change=SettingsState.set_license_blocklist_input,
                    class_name="w-full"
                ),
                rx.button("Enregistrer", on_click=SettingsState.save_license_blocklist, color_scheme="cyan"),
                spacing="3",
                width="100%"
            ),
            width="100%",
            spacing="2",
            class_name="p-6 rounded-xl bg-slate-2 border border-slate-4 shadow-sm mb-6"
        ),

        # Raw payload retention
        rx.vstack(
            rx.heading("Rétention des données brutes", size="3", weight="bold"),
            rx.text(
                "Les sorties brutes des scanners (SBOM et rapport de vulnérabilités) pèsent quelques "
                "mégaoctets par scan et ne servent qu'à l'audit. Elles sont purgées au-delà des seuils "
                "ci-dessous. Les problèmes suivis, les décisions de triage et les compteurs par scan ne "
                "sont jamais touchés : c'est la projection normalisée qui fait office d'historique.",
                size="2", color="var(--slate-10)", class_name="mb-2"
            ),
            rx.hstack(
                rx.vstack(
                    rx.text("Scans conservés par cible", size="2", weight="medium"),
                    rx.input(
                        value=SettingsState.retention_keep_input,
                        on_change=SettingsState.set_retention_keep_input,
                        placeholder=str(DEFAULT_KEEP_PER_TARGET),
                        class_name="w-full",
                    ),
                    spacing="1", width="100%",
                ),
                rx.vstack(
                    rx.text("Âge maximum (jours)", size="2", weight="medium"),
                    rx.input(
                        value=SettingsState.retention_max_age_input,
                        on_change=SettingsState.set_retention_max_age_input,
                        placeholder=str(DEFAULT_MAX_AGE_DAYS),
                        class_name="w-full",
                    ),
                    spacing="1", width="100%",
                ),
                rx.button(
                    "Enregistrer",
                    on_click=SettingsState.save_retention_config,
                    color_scheme="cyan",
                    class_name="self-end",
                ),
                spacing="3", width="100%", align="end",
            ),
            rx.callout(
                "Une sortie brute n'est purgée que si elle sort des DEUX seuils : un dépôt scanné deux "
                "fois par an garde ses données, un dépôt scanné toutes les heures reste borné. 0 dans un "
                "champ = pas de limite sur cet axe ; 0 dans les deux = purge désactivée.",
                icon="info", color_scheme="blue", size="1", class_name="mt-3"
            ),
            width="100%",
            spacing="2",
            class_name="p-6 rounded-xl bg-slate-2 border border-slate-4 shadow-sm mb-6"
        ),

        # Notifications
        rx.vstack(
            rx.heading("Notifications", size="3", weight="bold"),
            rx.text(
                "Envoie un webhook HTTP (JSON) quand un scan fait apparaître ou réapparaître un problème. "
                "Compatible Slack, Teams, Discord, Mattermost ou tout endpoint interne : le corps contient un "
                "champ « text » lisible tel quel, en plus des données structurées. Rien n'est envoyé quand un "
                "scan ne change rien — c'est le seul moyen qu'un canal reste lu.",
                size="2", color="var(--slate-10)", class_name="mb-2"
            ),
            rx.text(
                "Le message est écrit en base dans la même transaction que les résultats du "
                "scan, puis livré par l'ordonnanceur avec réessais espacés. Un webhook "
                "momentanément injoignable ne perd donc plus sa notification.",
                size="1", color="var(--slate-10)", class_name="mb-2"
            ),
            rx.cond(
                (SettingsState.outbox_pending > 0) | (SettingsState.outbox_failed > 0),
                rx.hstack(
                    rx.cond(
                        SettingsState.outbox_pending > 0,
                        rx.badge(
                            SettingsState.outbox_pending, " en attente",
                            color_scheme="amber", variant="soft",
                        ),
                    ),
                    rx.cond(
                        SettingsState.outbox_failed > 0,
                        rx.badge(
                            SettingsState.outbox_failed, " abandonnée(s)",
                            color_scheme="red", variant="soft",
                        ),
                    ),
                    rx.text(
                        "Une notification abandonnée l'a été après plusieurs heures de "
                        "tentatives ; le journal d'audit en donne la raison.",
                        size="1", color="var(--slate-10)",
                    ),
                    spacing="2",
                    align="center",
                    class_name="mb-2",
                ),
            ),
            rx.hstack(
                rx.input(
                    placeholder="https://hooks.slack.com/services/... (vide = notifications désactivées)",
                    value=SettingsState.notification_webhook_url_input,
                    on_change=SettingsState.set_notification_webhook_url_input,
                    type="password",
                    class_name="w-full"
                ),
                rx.button("Enregistrer", on_click=SettingsState.save_notification_config, color_scheme="cyan"),
                spacing="3",
                width="100%"
            ),
            rx.text("Seuil de sévérité", size="2", weight="medium", class_name="mt-3"),
            rx.select.root(
                rx.select.trigger(placeholder="Seuil..."),
                rx.select.content(
                    rx.select.group(
                        rx.foreach(
                            NOTIFICATION_SEVERITY_OPTIONS,
                            lambda opt: rx.select.item(opt["label"], value=opt["value"])
                        )
                    )
                ),
                value=SettingsState.notification_min_severity,
                on_change=SettingsState.set_notification_min_severity,
                width="100%"
            ),
            rx.hstack(
                rx.switch(
                    checked=SettingsState.notification_always_on_kev,
                    on_change=SettingsState.set_notification_always_on_kev,
                ),
                rx.text(
                    "Notifier toujours les vulnérabilités activement exploitées (CISA KEV), quelle que soit "
                    "leur sévérité",
                    size="2",
                ),
                spacing="3", align="center", class_name="mt-3"
            ),
            rx.callout(
                "L'URL est traitée comme un secret : elle n'est ni réaffichée en clair dans le journal "
                "d'audit, ni incluse dans les messages d'erreur (les URL Slack/Teams/Discord contiennent "
                "un jeton).",
                icon="shield", color_scheme="blue", size="1", class_name="mt-3"
            ),
            width="100%",
            spacing="2",
            class_name="p-6 rounded-xl bg-slate-2 border border-slate-4 shadow-sm mb-6"
        ),

        # AI code review (Ollama)
        rx.vstack(
            rx.heading("Revue de code par IA (optionnelle)", size="3", weight="bold"),
            rx.text(
                "Complément léger à Grype/gitleaks/checkov : un modèle local via Ollama, avec un prompt "
                "\"security architect\", pour un avis rapide en plus des scanners dédiés — pas un moteur SAST "
                "structuré. Désactivé par défaut. Nécessite un serveur Ollama accessible, installé nativement "
                "ou lancé via Docker (voir docs/GETTING_STARTED.md §7).",
                size="2", color="var(--slate-10)", class_name="mb-2"
            ),
            rx.hstack(
                rx.switch(
                    checked=SettingsState.ai_review_enabled,
                    on_change=SettingsState.set_ai_review_enabled,
                ),
                rx.text(
                    rx.cond(SettingsState.ai_review_enabled, "Activée", "Désactivée"),
                    size="2", weight="medium"
                ),
                spacing="3",
                align="center",
                class_name="mb-3"
            ),
            rx.vstack(
                rx.text("Mode de déploiement d'Ollama", size="1", weight="medium"),
                rx.select.root(
                    rx.select.trigger(placeholder="Choisir un mode...", width="100%"),
                    rx.select.content(
                        rx.select.group(
                            rx.foreach(
                                AI_REVIEW_DEPLOYMENT_MODE_OPTIONS,
                                lambda opt: rx.select.item(opt["label"], value=opt["value"])
                            )
                        )
                    ),
                    value=SettingsState.ai_review_deployment_mode,
                    on_change=SettingsState.set_ai_review_deployment_mode,
                    width="100%"
                ),
                rx.cond(
                    SettingsState.ai_review_deployment_mode == "docker",
                    rx.callout(
                        "Sur Mac (Apple Silicon), Docker Desktop n'a pas d'accès GPU/Metal : Ollama tourne "
                        "alors en CPU uniquement dans le conteneur, plus lent qu'une installation native. "
                        "Sur Linux avec GPU NVIDIA (+ nvidia-container-toolkit), l'accélération GPU reste "
                        "possible en conteneur. Voir docker-compose.ollama.yml à la racine du projet.",
                        icon="triangle-alert", color_scheme="amber", size="1", class_name="mt-2"
                    ),
                    rx.callout(
                        "Installation native recommandée : profite de l'accélération GPU (Metal sur Mac Apple "
                        "Silicon, CUDA/ROCm sur Linux) — voir docs/GETTING_STARTED.md §7.",
                        icon="info", color_scheme="green", size="1", class_name="mt-2"
                    )
                ),
                width="100%", spacing="1", class_name="mb-3"
            ),
            rx.vstack(
                rx.text("URL du serveur Ollama", size="1", weight="medium"),
                rx.hstack(
                    rx.input(
                        placeholder=DEFAULT_OLLAMA_URL,
                        value=SettingsState.ai_review_ollama_url_input,
                        on_change=SettingsState.set_ai_review_ollama_url_input,
                        class_name="w-full"
                    ),
                    rx.button(
                        "Enregistrer",
                        on_click=SettingsState.save_ai_review_ollama_url,
                        color_scheme="cyan"
                    ),
                    spacing="3",
                    width="100%"
                ),
                width="100%", spacing="1", class_name="mb-3"
            ),
            rx.vstack(
                rx.hstack(
                    rx.text("Modèle", size="1", weight="medium"),
                    rx.button(
                        "Rafraîchir la liste",
                        on_click=SettingsState.refresh_ai_review_models,
                        loading=SettingsState.ai_review_models_loading,
                        variant="soft",
                        size="1"
                    ),
                    justify="between",
                    width="100%",
                    align="center"
                ),
                rx.select.root(
                    rx.select.trigger(placeholder="Choisir un modèle...", width="100%"),
                    rx.select.content(
                        rx.select.group(
                            rx.foreach(
                                SettingsState.ai_review_available_models,
                                lambda model: rx.select.item(model, value=model)
                            )
                        )
                    ),
                    value=SettingsState.ai_review_model,
                    on_change=SettingsState.set_ai_review_model,
                    width="100%"
                ),
                rx.text(
                    "Liste lue en direct sur l'API d'Ollama (/api/tags) — reflète les modèles réellement "
                    "installés (`ollama pull ...`), pas une liste figée. Si Ollama est injoignable, des "
                    "suggestions (Gemma 4 12B/E4B QAT) sont proposées à la place.",
                    size="1", color="var(--slate-10)", class_name="mt-1"
                ),
                width="100%", spacing="1"
            ),
            width="100%",
            spacing="2",
            class_name="p-6 rounded-xl bg-slate-2 border border-slate-4 shadow-sm"
        ),

        width="100%",
        spacing="4",
        on_mount=SettingsState.load_settings
    )

    return main_layout(content, "Paramètres")
