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

    @requires_admin
    def load_settings(self):
        self.set_current_page("Paramètres")
        container = get_container()
        try:
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
            self.notification_webhook_url_input = container.notification_service.webhook_url()
            self.notification_min_severity = container.notification_service.min_severity()
            self.notification_always_on_kev = container.notification_service.always_on_kev()
        except Exception as e:
            yield self.trigger_toast(f"Erreur de chargement : {str(e)}", is_error=True)
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

    def set_notification_webhook_url_input(self, value: str):
        self.notification_webhook_url_input = value

    @requires_admin
    def save_notification_config(self):
        container = get_container()
        try:
            url = self.notification_webhook_url_input.strip()
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
