import reflex as rx
from typing import List, Dict, Any
import uuid
import asyncio

from zanshin.ui.state import BaseState
from zanshin.ui.auth import requires_login
from zanshin.ui.layout import main_layout
from zanshin.ui.components import (
    actionable_badge,
    count_badge,
    delta_badges,
    empty_state,
    severity_badges,
    severity_donut_chart,
    severity_summary,
    stat_card,
    status_badge,
)
from zanshin.container import get_container
from zanshin.ui.view_models import (
    AiFindingRow,
    RepoScanRow,
    RepositoryRow,
    ScanRow,
    AiReviewSummary,
    IacRow,
    SastRow,
    LicenseRow,
    SecretRow,
    SeverityCounts,
    VulnerabilityRow,
    format_datetime,
    format_percent,
    format_score,
    severity_chart,
    safe_external_url,
    severity_color,
)
from zanshin.models.repository import ZanshinRepository
from zanshin.services.cron import (
    InvalidCronExpression,
    next_occurrence as next_cron_occurrence,
    validate_expression as validate_cron,
)
from zanshin.models.scan import Scan

def _describe_cron(expression) -> str:
    """A one-line answer to "when does this next fire", or the reason it never will."""
    expression = (expression or "").strip()
    if not expression:
        return ""
    try:
        validate_cron(expression)
    except InvalidCronExpression:
        return "Expression invalide — la planification par intervalle reste utilisée."
    upcoming = next_cron_occurrence(expression)
    if upcoming is None:
        return ""
    return f"Prochaine exécution : {format_datetime(upcoming)} (UTC)"


class DepotsState(BaseState):
    """Manages the Git repositories configuration, planning, and unified global scan history."""

    repositories: list[RepositoryRow] = []
    ssh_keys_list: list[dict[str, str]] = []  # label/value pairs for a select, not a row model

    # Aggregated metrics (latest scan of each repo), for the KPI row and
    # severity donut chart shown above the tabs.
    total_vulns: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    secret_count: int = 0
    # Dicts, not a row model: see `severity_chart` for why.
    severity_chart_data: list[dict[str, Any]] = []

    # Global Scan History
    scan_history: list[ScanRow] = []
    search_history_query: str = ""
    
    # Add Repo modal variables
    dialog_open: bool = False
    new_name: str = ""
    new_url: str = ""
    new_branch: str = "main"
    new_sub_path: str = ""
    new_ssh_key_id: str = ""
    new_interval: int = 1440

    # Repo details view variables
    selected_repo_id: int = 0
    selected_repo_name: str = ""
    selected_repo_url: str = ""
    selected_repo_branch: str = ""
    selected_repo_cron: str = ""
    # What the expression actually means, recomputed as it is typed. A cron expression
    # is the kind of input that is easy to get subtly wrong and impossible to verify by
    # re-reading — so the screen answers "when does this next fire" instead of leaving
    # the operator to find out by watching scans not happen.
    selected_repo_cron_hint: str = ""
    selected_repo_interval: int = 1440
    selected_repo_scans: list[RepoScanRow] = []
    is_viewing_details: bool = False

    # CVE details dialog variables
    cve_dialog_open: bool = False
    selected_scan_name: str = ""
    selected_scan_cves: list[VulnerabilityRow] = []
    selected_scan_summary: SeverityCounts = SeverityCounts()
    selected_scan_secrets: list[SecretRow] = []
    selected_scan_licenses: list[LicenseRow] = []
    selected_scan_iac: list[IacRow] = []
    selected_scan_sast: list[SastRow] = []
    selected_scan_ai_review: AiReviewSummary = AiReviewSummary()
    selected_scan_ai_findings: list[AiFindingRow] = []

    def set_new_name(self, val: str):
        self.new_name = val

    def set_new_url(self, val: str):
        self.new_url = val

    def set_new_branch(self, val: str):
        self.new_branch = val

    def set_new_sub_path(self, val: str):
        self.new_sub_path = val

    def set_new_ssh_key_id(self, val: str):
        self.new_ssh_key_id = val

    def set_selected_repo_name(self, val: str):
        self.selected_repo_name = val

    def set_selected_repo_cron(self, val: str):
        self.selected_repo_cron = val
        self.selected_repo_cron_hint = _describe_cron(val)

    def set_search_history_query(self, val: str):
        self.search_history_query = val
        return DepotsState.load_history_list(self)

    @requires_login
    def load_repositories_data(self):
        self.set_current_page("Dépôts & Scans")
        yield DepotsState.load_repos_list(self)
        yield DepotsState.load_history_list(self)

    @requires_login
    def load_repos_list(self):
        container = get_container()
        try:
            db_repos = container.repository_repository.find_all()

            # Latest scan per repo as column-only summaries: this list needs
            # status/counts, never the raw SBOM or CVE blobs (see ScanSummary).
            latest_scans = container.scan_repository.find_latest_summary_by_repository_ids(
                [r.id for r in db_repos]
            )

            secret_counts = container.finding_repository.count_by_scan_ids_and_type(
                [s.id for s in latest_scans.values()], "secret"
            )
            # Outstanding (open, not yet settled by triage) issues per repo —
            # the number that actually means "work to do", unlike a raw finding
            # count which re-reports everything already reviewed.
            actionable_counts = container.issue_repository.count_actionable_by_repo_ids(
                [r.id for r in db_repos]
            )

            self.repositories = []
            totals = SeverityCounts()
            total_vulns = 0
            total_secrets = 0
            for r in db_repos:
                latest = latest_scans.get(r.id)
                counts = SeverityCounts.from_summary(latest.summary if latest else None)
                secrets = secret_counts.get(latest.id, 0) if latest else 0
                if latest:
                    total_vulns += latest.findings_count
                    total_secrets += secrets
                    totals.critical += counts.critical
                    totals.high += counts.high
                    totals.medium += counts.medium
                    totals.low += counts.low

                self.repositories.append(RepositoryRow(
                    id=r.id,
                    name=r.name or r.url,
                    url=r.url,
                    branch=r.branch,
                    status=latest.status if latest else "Non scanné",
                    findings=latest.findings_count if latest else 0,
                    counts=counts,
                    secrets=secrets,
                    open_issues=actionable_counts.get(r.id, 0),
                    last_scan_at=format_datetime(latest.created_at) if latest else "",
                ))

            self.total_vulns = total_vulns
            self.critical_count = totals.critical
            self.high_count = totals.high
            self.medium_count = totals.medium
            self.low_count = totals.low
            self.secret_count = total_secrets
            self.severity_chart_data = severity_chart(totals)

            # Load SSH Keys for dropdown selection
            db_keys = container.ssh_key_repository.find_all()
            self.ssh_keys_list = [{"label": k.name, "value": str(k.id)} for k in db_keys]
        except Exception as e:
            yield self.trigger_toast(f"Erreur de chargement : {str(e)}", is_error=True)
        finally:
            container.db.close()

    @requires_login
    def load_history_list(self):
        container = get_container()
        try:
            # One join-based query, newest first, with no raw scanner output
            # loaded and no per-row lazy load of the scanned target — which
            # previously pulled each repository's *entire* scan collection
            # back through `s.repository` (see ScanHistoryRow).
            history_rows = container.scan_repository.find_history_rows()
            self.scan_history = []
            filter_query = self.search_history_query.lower()

            secret_counts = container.finding_repository.count_by_scan_ids_and_type(
                [row.scan.id for row in history_rows], "secret"
            )

            for row in history_rows:
                s = row.scan
                if row.repo_id:
                    target_name = row.repo_name or row.repo_url or "Dépôt inconnu"
                    branch = s.branch or "main"
                else:
                    target_name = row.image_string or "Image inconnue"
                    branch = "—"

                if filter_query and all(
                    filter_query not in value.lower()
                    for value in (target_name, branch, s.status or "")
                ):
                    continue

                self.scan_history.append(ScanRow(
                    id=s.id,
                    repo_id=str(row.repo_id) if row.repo_id else "",
                    target_name=target_name,
                    branch=branch,
                    status=s.status or "pending",
                    findings=s.findings_count,
                    counts=SeverityCounts.from_summary(s.summary),
                    secrets=secret_counts.get(s.id, 0),
                    new_issues=s.new_issues_count,
                    resolved_issues=s.resolved_issues_count,
                    duration=f"{s.duration_ms // 1000}s" if s.duration_ms else "—",
                    created_at=format_datetime(s.created_at, "%d/%m/%y %H:%M"),
                ))
        except Exception as e:
            yield self.trigger_toast(f"Erreur de chargement de l'historique : {str(e)}", is_error=True)
        finally:
            container.db.close()

    def set_new_interval(self, val: str):
        try:
            self.new_interval = int(val) if val else 1440
        except ValueError:
            self.new_interval = 1440

    def set_selected_repo_interval(self, val: str):
        try:
            self.selected_repo_interval = int(val) if val else 1440
        except ValueError:
            self.selected_repo_interval = 1440

    @requires_login
    def add_repository(self):
        if not self.new_url:
            yield self.trigger_toast("L'URL du dépôt est requise", is_error=True)
            return

        container = get_container()
        try:
            ssh_uuid = uuid.UUID(self.new_ssh_key_id) if self.new_ssh_key_id else None

            new_r = ZanshinRepository(
                name=self.new_name if self.new_name else None,
                url=self.new_url,
                branch=self.new_branch,
                sub_path=self.new_sub_path if self.new_sub_path else None,
                ssh_key_id=ssh_uuid,
                scan_interval_minutes=self.new_interval
            )
            # Via the service, not the repository: that's where the URL is
            # checked against the transports git may only fetch from (see
            # zanshin/services/git_url.py). A rejected URL raises ValueError
            # and is reported by the `except` below.
            container.repository_service.save(new_r)


            self.new_name = ""
            self.new_url = ""
            self.new_branch = "main"
            self.new_sub_path = ""
            self.new_ssh_key_id = ""
            self.new_interval = 1440
            self.dialog_open = False
            
            yield self.trigger_toast("Dépôt ajouté avec succès")
            yield DepotsState.load_repositories_data(self)
        except Exception as e:
            yield self.trigger_toast(f"Erreur d'ajout : {str(e)}", is_error=True)
        finally:
            container.db.close()

    @requires_login
    async def trigger_scan(self, repo_id: int):
        container_ioc = get_container()
        try:
            container_ioc.repository_service.trigger_scan(repo_id)
            yield self.trigger_toast("Scan de dépôt démarré en arrière-plan")
            await asyncio.sleep(1)
            yield DepotsState.load_repositories_data(self)
            if self.is_viewing_details and self.selected_repo_id == repo_id:
                yield DepotsState.view_details(self, repo_id)
        except Exception as e:
            yield self.trigger_toast(f"Erreur de scan : {str(e)}", is_error=True)
        finally:
            container_ioc.db.close()

    @requires_login
    async def relaunch_scan(self, repo_id_str: str):
        if not repo_id_str:
            yield self.trigger_toast("Dépôt non associé à ce scan", is_error=True)
            return
        yield DepotsState.trigger_scan(self, int(repo_id_str))

    @requires_login
    def delete_scan(self, scan_id_str: str):
        container = get_container()
        try:
            scan_id = int(scan_id_str)
            container.scan_repository.delete_by_id(scan_id)
            yield self.trigger_toast("Enregistrement de scan supprimé")
            yield DepotsState.load_history_list(self)
        except Exception as e:
            yield self.trigger_toast(f"Erreur de suppression : {str(e)}", is_error=True)
        finally:
            container.db.close()

    @requires_login
    def delete_repository(self, repo_id: int):
        container = get_container()
        try:
            container.repository_repository.delete_by_id(repo_id)
            yield self.trigger_toast("Dépôt supprimé")
            yield DepotsState.load_repositories_data(self)
        except Exception as e:
            yield self.trigger_toast(f"Erreur de suppression : {str(e)}", is_error=True)
        finally:
            container.db.close()

    @requires_login
    def view_details(self, repo_id: int):
        container = get_container()
        try:
            r = container.repository_repository.find_by_id(repo_id)
            if not r:
                return
            
            self.selected_repo_id = r.id
            self.selected_repo_name = r.name or ""
            self.selected_repo_url = r.url
            self.selected_repo_branch = r.branch
            self.selected_repo_cron = r.scan_cron or ""
            self.selected_repo_cron_hint = _describe_cron(r.scan_cron)
            self.selected_repo_interval = r.scan_interval_minutes or 1440
            
            # Load scans list (summaries only — no SBOM/CVE blobs)
            scans = container.scan_repository.find_summaries_by_repository_id(r.id)
            secret_counts = container.finding_repository.count_by_scan_ids_and_type(
                [s.id for s in scans], "secret"
            )
            self.selected_repo_scans = [
                RepoScanRow(
                    id=s.id,
                    branch=s.branch,
                    status=s.status,
                    findings=s.findings_count,
                    counts=SeverityCounts.from_summary(s.summary),
                    secrets=secret_counts.get(s.id, 0),
                    new_issues=s.new_issues_count,
                    resolved_issues=s.resolved_issues_count,
                    created_at=format_datetime(s.created_at),
                )
                for s in scans
            ]

            self.is_viewing_details = True
        except Exception as e:
            yield self.trigger_toast(f"Erreur de lecture : {str(e)}", is_error=True)
        finally:
            container.db.close()

    @requires_login
    def save_config(self):
        container = get_container()
        try:
            db = container.db
            r = db.query(ZanshinRepository).filter(ZanshinRepository.id == self.selected_repo_id).first()
            if not r:
                return
            
            r.name = self.selected_repo_name if self.selected_repo_name else None
            r.scan_interval_minutes = self.selected_repo_interval
            r.scan_cron = self.selected_repo_cron if self.selected_repo_cron else None
            # Through the service, not a bare commit: that is where the cron expression
            # is validated, and a screen that wrote around it would put an unschedulable
            # value in the database — the exact defect this replaces.
            container.repository_service.save(r)

            self.selected_repo_cron_hint = _describe_cron(r.scan_cron)
            yield self.trigger_toast("Configuration enregistrée")
            yield DepotsState.load_repositories_data(self)
        except InvalidCronExpression as e:
            db.rollback()
            yield self.trigger_toast(str(e), is_error=True)
        except Exception as e:
            yield self.trigger_toast(f"Erreur d'enregistrement : {str(e)}", is_error=True)
        finally:
            container.db.close()

    def exit_details(self):
        self.is_viewing_details = False

    @requires_login
    def show_cves(self, scan_id: int):
        container = get_container()
        try:
            db = container.db
            s = db.query(Scan).filter(Scan.id == scan_id).first()
            if not s:
                return
            
            target_info = ""
            if s.repo_id:
                target_info = s.repository.name or s.repository.url
            elif s.container_id:
                target_info = s.container.image_string if s.container else "Image inconnue"
                
            self.selected_scan_name = f"Scan #{s.id} ({target_info})"
            
            # Built from the normalized `Finding` rows, not from `Scan.cves`.
            # Two reasons: the raw blob is what the retention policy drops (see
            # RetentionService), and every field this dialog shows —
            # severity, CVSS, EPSS, KEV, fix version, link — is already on the
            # finding. Reading the blob meant re-parsing tool-specific JSON to
            # recover data we had already normalized.
            self.selected_scan_cves = [
                VulnerabilityRow(
                    identifier=f.identifier or "N/A",
                    severity=(f.severity or "unknown").upper(),
                    severity_color=severity_color(f.severity),
                    component=f.package_name or "N/A",
                    version=f.package_version or "",
                    cvss=format_score(f.cvss_score),
                    epss=format_percent(f.epss_score),
                    is_kev=bool(f.is_kev),
                    fix=f.fix_versions or ("Aucun correctif" if f.fix_state in ("not-fixed", "wont-fix") else "—"),
                    link=safe_external_url(f.link),
                )
                for f in container.finding_repository.find_all_by_scan_id_and_type(scan_id, "vulnerability")
            ]

            self.selected_scan_secrets = [
                SecretRow(rule=f.identifier or "N/A", file_path=f.file_path or "N/A")
                for f in container.finding_repository.find_all_by_scan_id_and_type(scan_id, "secret")
            ]

            self.selected_scan_licenses = [
                LicenseRow(
                    license=f.identifier or "N/A",
                    component=f"{f.package_name or 'N/A'} {f.package_version or ''}".strip(),
                )
                for f in container.finding_repository.find_all_by_scan_id_and_type(scan_id, "license")
            ]

            self.selected_scan_iac = [
                IacRow(
                    severity=(f.severity or "medium").upper(),
                    severity_color=severity_color(f.severity or "medium"),
                    check_id=f.identifier or "N/A",
                    resource=f.package_name or "N/A",
                    file_path=f.file_path or "N/A",
                )
                for f in container.finding_repository.find_all_by_scan_id_and_type(scan_id, "iac")
            ]

            # Semgrep, both halves in one table: a reviewer reading a scan wants the
            # whole of what the code analysis said, and the badge carries which half
            # each line belongs to.
            self.selected_scan_sast = [
                SastRow(
                    severity=(f.severity or "unknown").upper(),
                    severity_color=severity_color(f.severity or "unknown"),
                    rule_id=f.identifier or "N/A",
                    message=f.description or "",
                    file_path=f.file_path or "N/A",
                    line=str(f.line) if f.line else "",
                    kind=f.type,
                    kind_label="Sécurité" if f.type == "sast" else "Qualité",
                    kind_color="red" if f.type == "sast" else "blue",
                )
                for kind in ("sast", "quality")
                for f in container.finding_repository.find_all_by_scan_id_and_type(scan_id, kind)
            ]

            # Optional AI code review (Ollama, see ADR-001 Phase 8) — at most one
            # row per scan, absent unless the feature was enabled when it ran.
            ai_review = container.ai_review_result_repository.find_by_scan_id(scan_id)
            self.selected_scan_ai_review = AiReviewSummary(
                present=True,
                model=ai_review.model,
                status=ai_review.status,
                response=ai_review.response or "",
                error=ai_review.error or "",
            ) if ai_review else AiReviewSummary()

            self.selected_scan_ai_findings = [
                AiFindingRow(
                    severity=(f.severity or "unknown").upper(),
                    severity_color=severity_color(f.severity),
                    title=f.identifier or "N/A",
                    file_path=f.file_path or "—",
                )
                for f in container.finding_repository.find_all_by_scan_id_and_type(scan_id, "ai_review")
            ]

            self.selected_scan_summary = SeverityCounts.from_summary(s.summary)
            self.cve_dialog_open = True
        except Exception as e:
            yield self.trigger_toast(f"Erreur de lecture : {str(e)}", is_error=True)
        finally:
            container.db.close()

    def close_cves(self):
        self.cve_dialog_open = False

def list_layout_view() -> rx.Component:
    """Renders the repositories listing view."""
    return rx.vstack(
        rx.hstack(
            rx.text("Gérez les configurations et plannings de vos dépôts de code", size="2", color="var(--slate-10)"),
            rx.spacer(),
            # Add Repo modal dialog
            rx.dialog.root(
                rx.dialog.trigger(
                    rx.button("Ajouter un dépôt", rx.icon(tag="plus"), color_scheme="cyan")
                ),
                rx.dialog.content(
                    rx.dialog.title("Ajouter un dépôt Git"),
                    rx.dialog.description("Liez un dépôt Git pour analyser son code source."),
                    rx.vstack(
                        rx.vstack(
                            rx.text("Nom convivial (Optionnel)", size="2", weight="bold"),
                            rx.input(placeholder="Ex: Mon Backend API", value=DepotsState.new_name, on_change=DepotsState.set_new_name, class_name="w-full"),
                            width="100%", spacing="1"
                        ),
                        rx.vstack(
                            rx.text("URL Git (HTTPS ou SSH)", size="2", weight="bold"),
                            rx.input(placeholder="Ex: git@github.com:user/repo.git", value=DepotsState.new_url, on_change=DepotsState.set_new_url, required=True, class_name="w-full"),
                            width="100%", spacing="1"
                        ),
                        rx.vstack(
                            rx.text("Branche", size="2", weight="bold"),
                            rx.input(placeholder="Ex: main", value=DepotsState.new_branch, on_change=DepotsState.set_new_branch, class_name="w-full"),
                            width="100%", spacing="1"
                        ),
                        rx.vstack(
                            rx.text("Sous-répertoire (Optionnel)", size="2", weight="bold"),
                            rx.input(placeholder="Ex: src/main", value=DepotsState.new_sub_path, on_change=DepotsState.set_new_sub_path, class_name="w-full"),
                            width="100%", spacing="1"
                        ),
                        rx.vstack(
                            rx.text("Clé SSH associée (Optionnel)", size="2", weight="bold"),
                            rx.select.root(
                                rx.select.trigger(placeholder="Choisir une clé..."),
                                rx.select.content(
                                    rx.select.group(
                                        rx.foreach(
                                            DepotsState.ssh_keys_list,
                                            lambda k: rx.select.item(k["label"], value=k["value"])
                                        )
                                    )
                                ),
                                value=DepotsState.new_ssh_key_id,
                                on_change=DepotsState.set_new_ssh_key_id,
                                width="100%"
                            ),
                            width="100%", spacing="1"
                        ),
                        rx.vstack(
                            rx.text("Intervalle de scan (Minutes)", size="2", weight="bold"),
                            rx.input(type="number", value=DepotsState.new_interval.to(str), on_change=DepotsState.set_new_interval, class_name="w-full"),
                            width="100%", spacing="1"
                        ),
                        spacing="3",
                        class_name="mt-4 w-full"
                    ),
                    rx.hstack(
                        rx.dialog.close(
                            rx.button("Annuler", variant="soft", color_scheme="gray")
                        ),
                        rx.dialog.close(
                            rx.button("Enregistrer", on_click=DepotsState.add_repository, color_scheme="green")
                        ),
                        spacing="3",
                        class_name="mt-6 justify-end"
                    ),
                    class_name="max-w-xl w-full"
                )
            ),
            width="100%",
            align="center"
        ),
        
        # Grid/Table
        rx.cond(
            DepotsState.repositories.length() == 0,
            empty_state(
                "git-branch",
                "Aucun dépôt configuré pour le moment",
                "Ajoutez un dépôt Git ci-dessus pour démarrer ses analyses de sécurité.",
            ),
            rx.box(
            rx.table.root(
                rx.table.header(
                    rx.table.row(
                        rx.table.column_header_cell("Nom / Référence"),
                        rx.table.column_header_cell("URL Git"),
                        rx.table.column_header_cell("Branche"),
                        rx.table.column_header_cell("Statut"),
                        rx.table.column_header_cell("Vulnérabilités"),
                        rx.table.column_header_cell("Secrets"),
                        rx.table.column_header_cell("À traiter"),
                        rx.table.column_header_cell("Actions")
                    )
                ),
                rx.table.body(
                    rx.foreach(
                        DepotsState.repositories,
                        lambda r: rx.table.row(
                            rx.table.row_header_cell(r.name),
                            rx.table.cell(r.url),
                            rx.table.cell(r.branch),
                            rx.table.cell(status_badge(r.status)),
                            rx.table.cell(severity_badges(r.counts, r.findings)),
                            rx.table.cell(count_badge(r.secrets, f"{r.secrets} secret(s)")),
                            # Outstanding issues: open and not yet settled by a
                            # triage decision. Unlike the finding count on its
                            # left, this shrinks when the team works.
                            rx.table.cell(actionable_badge(r.open_issues)),
                            rx.table.cell(
                                rx.hstack(
                                    rx.tooltip(
                                        rx.button(
                                            rx.icon(tag="play"),
                                            size="2",
                                            color_scheme="green",
                                            variant="soft",
                                            on_click=lambda: DepotsState.trigger_scan(r.id)
                                        ),
                                        content="Lancer Scan"
                                    ),
                                    rx.tooltip(
                                        rx.button(
                                            rx.icon(tag="settings"),
                                            size="2",
                                            color_scheme="teal",
                                            variant="soft",
                                            on_click=lambda: DepotsState.view_details(r.id)
                                        ),
                                        content="Planification / Détails"
                                    ),
                                    rx.tooltip(
                                        rx.button(
                                            rx.icon(tag="trash"),
                                            size="2",
                                            color_scheme="red",
                                            variant="soft",
                                            on_click=lambda: DepotsState.delete_repository(r.id)
                                        ),
                                        content="Supprimer"
                                    ),
                                    spacing="2"
                                )
                            ),
                            class_name="hover:bg-slate-3/60 transition-colors"
                        )
                    )
                ),
                width="100%"
            ),
            width="100%",
            class_name="zs-card w-full"
            )
        ),
        width="100%"
    )

def history_layout_view() -> rx.Component:
    """Renders the global scans history list."""
    return rx.vstack(
        rx.hstack(
            rx.text("Historique de l'ensemble des analyses effectuées", size="2", color="var(--slate-10)"),
            rx.spacer(),
            rx.input(
                placeholder="Filtrer l'historique...",
                value=DepotsState.search_history_query,
                on_change=DepotsState.set_search_history_query,
                class_name="max-w-xs"
            ),
            width="100%",
            align="center"
        ),
        
        # Scans History Table
        rx.cond(
            DepotsState.scan_history.length() == 0,
            empty_state(
                "history",
                "Aucun scan pour le moment",
                "L'historique apparaîtra ici dès qu'un scan aura été lancé.",
            ),
            rx.box(
            rx.table.root(
                rx.table.header(
                    rx.table.row(
                        rx.table.column_header_cell("# ID"),
                        rx.table.column_header_cell("Cible de scan"),
                        rx.table.column_header_cell("Branche"),
                        rx.table.column_header_cell("Statut"),
                        rx.table.column_header_cell("Durée"),
                        rx.table.column_header_cell("Vulnérabilités"),
                        rx.table.column_header_cell("Secrets"),
                        rx.table.column_header_cell("Évolution"),
                        rx.table.column_header_cell("Date de scan"),
                        rx.table.column_header_cell("Actions")
                    )
                ),
                rx.table.body(
                    rx.foreach(
                        DepotsState.scan_history,
                        lambda s: rx.table.row(
                            rx.table.cell(f"#{s.id}"),
                            rx.table.row_header_cell(s.target_name),
                            rx.table.cell(s.branch),
                            rx.table.cell(status_badge(s.status)),
                            rx.table.cell(s.duration),
                            rx.table.cell(severity_badges(s.counts, s.findings)),
                            rx.table.cell(count_badge(s.secrets, f"{s.secrets} secret(s)")),
                            # What this scan changed relative to the previous one
                            # of the same target (see IssueService). The signal
                            # a raw finding count can't give: 400 findings that
                            # are all already known is not news.
                            rx.table.cell(delta_badges(s.new_issues, s.resolved_issues)),
                            rx.table.cell(s.created_at),
                            rx.table.cell(
                                rx.hstack(
                                    rx.tooltip(
                                        rx.button(
                                            rx.icon(tag="eye"),
                                            size="2",
                                            color_scheme="teal",
                                            variant="soft",
                                            on_click=lambda: DepotsState.show_cves(s.id)
                                        ),
                                        content="Détails (CVEs & secrets)"
                                    ),
                                    rx.cond(
                                        s.repo_id != "",
                                        rx.tooltip(
                                            rx.button(
                                                rx.icon(tag="refresh-cw"),
                                                size="2",
                                                color_scheme="green",
                                                variant="soft",
                                                on_click=lambda: DepotsState.relaunch_scan(s.repo_id)
                                            ),
                                            content="Re-scanner"
                                        )
                                    ),
                                    rx.tooltip(
                                        rx.button(
                                            rx.icon(tag="trash"),
                                            size="2",
                                            color_scheme="red",
                                            variant="soft",
                                            on_click=lambda: DepotsState.delete_scan(s.id.to_string())
                                        ),
                                        content="Supprimer"
                                    ),
                                    spacing="2"
                                )
                            ),
                            class_name="hover:bg-slate-3/60 transition-colors"
                        )
                    )
                ),
                width="100%"
            ),
            width="100%",
            class_name="zs-card w-full"
            )
        ),
        width="100%"
    )

def details_layout_view() -> rx.Component:
    """Renders the repository config edit form and scan history list."""
    return rx.vstack(
        # Header with back button
        rx.hstack(
            rx.button(
                "Retour", 
                rx.icon(tag="arrow-left"), 
                variant="ghost", 
                color_scheme="gray", 
                on_click=DepotsState.exit_details
            ),
            rx.heading(DepotsState.selected_repo_name, size="5", weight="bold"),
            align="center",
            spacing="3",
            width="100%",
            class_name="mb-4"
        ),
        
        # Configuration Edit Form
        rx.vstack(
            rx.heading("Configuration du dépôt", size="3", weight="bold"),
            rx.hstack(
                rx.vstack(
                    rx.text("Nom", size="2", weight="medium"),
                    rx.input(value=DepotsState.selected_repo_name, on_change=DepotsState.set_selected_repo_name, class_name="w-full"),
                    width="30%"
                ),
                rx.vstack(
                    rx.text("Intervalle de scan (Minutes)", size="2", weight="medium"),
                    rx.input(type="number", value=DepotsState.selected_repo_interval.to(str), on_change=DepotsState.set_selected_repo_interval, class_name="w-full"),
                    width="30%"
                ),
                rx.vstack(
                    rx.text("Expression Cron (Optionnel)", size="2", weight="medium"),
                    rx.input(
                        value=DepotsState.selected_repo_cron,
                        on_change=DepotsState.set_selected_repo_cron,
                        placeholder="Ex : 0 2 * * *",
                        class_name="w-full",
                    ),
                    rx.text(
                        rx.cond(
                            DepotsState.selected_repo_cron_hint != "",
                            DepotsState.selected_repo_cron_hint,
                            "Vide : l'intervalle ci-contre est utilisé.",
                        ),
                        size="1",
                        color="var(--slate-10)",
                    ),
                    width="30%",
                    spacing="1",
                ),
                rx.button("Enregistrer", on_click=DepotsState.save_config, color_scheme="cyan", class_name="self-end mb-1"),
                align="center",
                spacing="4",
                width="100%"
            ),
            width="100%",
            class_name="zs-card mb-6"
        ),
        
        # Scan history
        rx.vstack(
            rx.heading("Historique des scans du dépôt", size="3", weight="bold"),
            rx.box(
                rx.table.root(
                    rx.table.header(
                        rx.table.row(
                            rx.table.column_header_cell("# ID"),
                            rx.table.column_header_cell("Branche"),
                            rx.table.column_header_cell("Statut"),
                            rx.table.column_header_cell("Vulnérabilités"),
                            rx.table.column_header_cell("Secrets"),
                            rx.table.column_header_cell("Évolution"),
                            rx.table.column_header_cell("Date de début"),
                            rx.table.column_header_cell("Actions")
                        )
                    ),
                    rx.table.body(
                        rx.foreach(
                            DepotsState.selected_repo_scans,
                            lambda scan: rx.table.row(
                                rx.table.cell(f"#{scan.id}"),
                                rx.table.cell(scan.branch),
                                rx.table.cell(status_badge(scan.status)),
                                rx.table.cell(severity_badges(scan.counts, scan.findings)),
                                rx.table.cell(count_badge(scan.secrets, f"{scan.secrets} secret(s)")),
                                rx.table.cell(delta_badges(scan.new_issues, scan.resolved_issues)),
                                rx.table.cell(scan.created_at),
                                rx.table.cell(
                                    rx.tooltip(
                                        rx.button(
                                            rx.icon(tag="eye"),
                                            size="2",
                                            color_scheme="teal",
                                            variant="soft",
                                            on_click=lambda: DepotsState.show_cves(scan.id)
                                        ),
                                        content="Voir CVEs"
                                    )
                                ),
                                class_name="hover:bg-slate-3/60 transition-colors"
                            )
                        )
                    ),
                    width="100%"
                ),
                class_name="w-full zs-scrollbox overflow-hidden"
            ),
            width="100%"
        ),
        width="100%"
    )

def overview_summary() -> rx.Component:
    """KPI row + severity donut chart summarizing the latest scan of every
    configured repository — shown above the tabs, hidden while viewing a
    single repo's details."""
    return rx.vstack(
        rx.flex(
            stat_card("Dépôts", DepotsState.repositories.length().to(str), "git-branch"),
            stat_card("Vulnérabilités", rx.Var.create(f"{DepotsState.total_vulns}"),
                      "shield-alert", "orange", alert=DepotsState.total_vulns > 0),
            stat_card("Critiques", rx.Var.create(f"{DepotsState.critical_count}"),
                      "triangle-alert", "red", alert=DepotsState.critical_count > 0),
            stat_card("Secrets", rx.Var.create(f"{DepotsState.secret_count}"),
                      "key-round", "amber", alert=DepotsState.secret_count > 0),
            width="100%",
            spacing="4",
            flex_wrap="wrap",
            class_name="mb-2"
        ),
        severity_donut_chart(
            DepotsState.severity_chart_data,
            DepotsState.total_vulns > 0,
            subtitle="Par sévérité, sur le dernier scan de chaque dépôt",
        ),
        width="100%",
        spacing="4",
        class_name="mb-6"
    )

def depots_page() -> rx.Component:
    """Depots planning and configuration view component."""

    tabbed_view = rx.tabs.root(
        rx.tabs.list(
            rx.tabs.trigger(
                rx.hstack(rx.icon(tag="git-branch", size=16), rx.text("Gestion des Dépôts")),
                value="depots"
            ),
            rx.tabs.trigger(
                rx.hstack(rx.icon(tag="history", size=16), rx.text("Historique Global des Scans")),
                value="history"
            ),
            class_name="mb-6 border-b border-slate-4"
        ),
        rx.tabs.content(
            list_layout_view(),
            value="depots"
        ),
        rx.tabs.content(
            history_layout_view(),
            value="history"
        ),
        default_value="depots"
    )

    content = rx.vstack(
        rx.cond(
            DepotsState.is_viewing_details,
            details_layout_view(),
            rx.vstack(
                overview_summary(),
                tabbed_view,
                width="100%",
                spacing="0"
            )
        ),

        # CVE details modal dialog (shared)
        rx.dialog.root(
            rx.dialog.content(
                rx.dialog.title(f"Vulnérabilités de {DepotsState.selected_scan_name}"),
                rx.dialog.description("Détails des failles, secrets, licences non conformes, et manifestes IaC mal configurés identifiés"),
                
                severity_summary(DepotsState.selected_scan_summary),
                
                # CVE list table
                rx.box(
                    rx.table.root(
                        rx.table.header(
                            rx.table.row(
                                rx.table.column_header_cell("Sévérité"),
                                rx.table.column_header_cell("CVE ID"),
                                rx.table.column_header_cell("Composant"),
                                rx.table.column_header_cell("Version"),
                                rx.table.column_header_cell("CVSS"),
                                rx.table.column_header_cell("Correctif"),
                                rx.table.column_header_cell("EPSS"),
                                rx.table.column_header_cell("KEV")
                            )
                        ),
                        rx.table.body(
                            rx.foreach(
                                DepotsState.selected_scan_cves,
                                lambda cve: rx.table.row(
                                    rx.table.cell(
                                        rx.badge(cve.severity, color_scheme=cve.severity_color)
                                    ),
                                    rx.table.cell(
                                        rx.cond(
                                            cve.link != "",
                                            rx.link(cve.identifier, href=cve.link, is_external=True, class_name="text-cyan-9 hover:underline"),
                                            rx.text(cve.identifier)
                                        )
                                    ),
                                    rx.table.cell(cve.component),
                                    rx.table.cell(cve.version),
                                    rx.table.cell(cve.cvss),
                                    rx.table.cell(
                                        rx.badge(
                                            cve.fix,
                                            color_scheme=rx.cond(cve.fix == "Aucun correctif", "gray", "green"),
                                        )
                                    ),
                                    rx.table.cell(cve.epss),
                                    rx.table.cell(
                                        rx.cond(
                                            cve.is_kev,
                                            rx.badge("Exploitée activement", color_scheme="red", variant="solid"),
                                            rx.text("—", color="var(--slate-9)")
                                        )
                                    ),
                                    class_name="hover:bg-slate-3/60 transition-colors"
                                )
                            )
                        ),
                        width="100%"
                    ),
                    class_name="mt-6 max-h-96 overflow-y-auto zs-scrollbox"
                ),

                # Secrets section (gitleaks) — only rendered when relevant
                rx.cond(
                    DepotsState.selected_scan_secrets.length() > 0,
                    rx.vstack(
                        rx.heading(f"Secrets détectés ({DepotsState.selected_scan_secrets.length()})", size="3", weight="bold"),
                        rx.box(
                            rx.table.root(
                                rx.table.header(
                                    rx.table.row(
                                        rx.table.column_header_cell("Règle"),
                                        rx.table.column_header_cell("Fichier")
                                    )
                                ),
                                rx.table.body(
                                    rx.foreach(
                                        DepotsState.selected_scan_secrets,
                                        lambda leak: rx.table.row(
                                            rx.table.cell(rx.badge(leak.rule, color_scheme="red", variant="solid")),
                                            rx.table.cell(leak.file_path),
                                            class_name="hover:bg-slate-3/60 transition-colors"
                                        )
                                    )
                                ),
                                width="100%"
                            ),
                            class_name="max-h-64 overflow-y-auto zs-scrollbox"
                        ),
                        width="100%",
                        spacing="2",
                        class_name="mt-6"
                    )
                ),

                # License compliance section — only rendered when relevant
                # (empty unless a blocklist is configured in Paramètres)
                rx.cond(
                    DepotsState.selected_scan_licenses.length() > 0,
                    rx.vstack(
                        rx.heading(f"Licences non conformes ({DepotsState.selected_scan_licenses.length()})", size="3", weight="bold"),
                        rx.box(
                            rx.table.root(
                                rx.table.header(
                                    rx.table.row(
                                        rx.table.column_header_cell("Licence"),
                                        rx.table.column_header_cell("Composant")
                                    )
                                ),
                                rx.table.body(
                                    rx.foreach(
                                        DepotsState.selected_scan_licenses,
                                        lambda lic: rx.table.row(
                                            rx.table.cell(rx.badge(lic.license, color_scheme="orange", variant="solid")),
                                            rx.table.cell(lic.component),
                                            class_name="hover:bg-slate-3/60 transition-colors"
                                        )
                                    )
                                ),
                                width="100%"
                            ),
                            class_name="max-h-64 overflow-y-auto zs-scrollbox"
                        ),
                        width="100%",
                        spacing="2",
                        class_name="mt-6"
                    )
                ),

                # Infrastructure-as-Code section (checkov) — only rendered
                # when relevant, repo scans only
                rx.cond(
                    DepotsState.selected_scan_iac.length() > 0,
                    rx.vstack(
                        rx.heading(f"Infrastructure as Code ({DepotsState.selected_scan_iac.length()})", size="3", weight="bold"),
                        rx.box(
                            rx.table.root(
                                rx.table.header(
                                    rx.table.row(
                                        rx.table.column_header_cell("Sévérité"),
                                        rx.table.column_header_cell("Check"),
                                        rx.table.column_header_cell("Ressource"),
                                        rx.table.column_header_cell("Fichier")
                                    )
                                ),
                                rx.table.body(
                                    rx.foreach(
                                        DepotsState.selected_scan_iac,
                                        lambda check: rx.table.row(
                                            rx.table.cell(
                                                rx.badge(check.severity, color_scheme=check.severity_color)
                                            ),
                                            rx.table.cell(check.check_id),
                                            rx.table.cell(check.resource),
                                            rx.table.cell(check.file_path),
                                            class_name="hover:bg-slate-3/60 transition-colors"
                                        )
                                    )
                                ),
                                width="100%"
                            ),
                            class_name="max-h-64 overflow-y-auto zs-scrollbox"
                        ),
                        width="100%",
                        spacing="2",
                        class_name="mt-6"
                    )
                ),

                # Semgrep source-code analysis — security and quality in one table,
                # each line badged with which it is. Every occurrence is listed here:
                # the backlog folds all hits of one rule in one file into a single
                # issue, so this is the only place the individual lines show up.
                rx.cond(
                    DepotsState.selected_scan_sast.length() > 0,
                    rx.vstack(
                        rx.heading(
                            f"Analyse du code source ({DepotsState.selected_scan_sast.length()})",
                            size="3", weight="bold",
                        ),
                        rx.box(
                            rx.table.root(
                                rx.table.header(
                                    rx.table.row(
                                        rx.table.column_header_cell("Sévérité"),
                                        rx.table.column_header_cell("Nature"),
                                        rx.table.column_header_cell("Règle"),
                                        rx.table.column_header_cell("Constat"),
                                        rx.table.column_header_cell("Emplacement"),
                                    )
                                ),
                                rx.table.body(
                                    rx.foreach(
                                        DepotsState.selected_scan_sast,
                                        lambda hit: rx.table.row(
                                            rx.table.cell(
                                                rx.badge(hit.severity, color_scheme=hit.severity_color)
                                            ),
                                            rx.table.cell(
                                                rx.badge(
                                                    hit.kind_label,
                                                    color_scheme=hit.kind_color,
                                                    variant="soft",
                                                )
                                            ),
                                            rx.table.cell(hit.rule_id),
                                            rx.table.cell(
                                                rx.text(hit.message, size="2")
                                            ),
                                            rx.table.cell(
                                                rx.cond(
                                                    hit.line != "",
                                                    f"{hit.file_path}:{hit.line}",
                                                    hit.file_path,
                                                )
                                            ),
                                            class_name="hover:bg-slate-3/60 transition-colors"
                                        )
                                    )
                                ),
                                width="100%"
                            ),
                            class_name="max-h-64 overflow-y-auto zs-scrollbox"
                        ),
                        rx.text(
                            "Les constats de qualité n'entrent jamais dans le verdict du "
                            "gate CI.",
                            size="1", color="var(--slate-10)",
                        ),
                        width="100%",
                        spacing="2",
                        class_name="mt-6"
                    )
                ),

                # Optional AI code review (Ollama, see ADR-001 Phase 8) —
                # only rendered when a review actually ran for this scan
                # (feature is disabled by default).
                rx.cond(
                    DepotsState.selected_scan_ai_review.present,
                    rx.vstack(
                        rx.hstack(
                            rx.heading("Revue de code par IA", size="3", weight="bold"),
                            rx.badge(
                                DepotsState.selected_scan_ai_review.model,
                                color_scheme="purple", variant="soft"
                            ),
                            rx.cond(
                                DepotsState.selected_scan_ai_review.status == "failed",
                                rx.badge("Échec", color_scheme="red", variant="solid")
                            ),
                            align="center",
                            spacing="2"
                        ),
                        rx.cond(
                            DepotsState.selected_scan_ai_review.status == "failed",
                            rx.callout(
                                DepotsState.selected_scan_ai_review.error,
                                icon="triangle-alert", color_scheme="red", size="1"
                            ),
                            rx.box(
                                rx.text(
                                    DepotsState.selected_scan_ai_review.response,
                                    size="2", white_space="pre-wrap"
                                ),
                                class_name="p-4 max-h-64 overflow-y-auto zs-scrollbox"
                            )
                        ),
                        # Normalized findings extracted from the response
                        # (see AiReviewService.parse_findings) — only shown
                        # when the model's response actually parsed.
                        rx.cond(
                            DepotsState.selected_scan_ai_findings.length() > 0,
                            rx.box(
                                rx.table.root(
                                    rx.table.header(
                                        rx.table.row(
                                            rx.table.column_header_cell("Sévérité"),
                                            rx.table.column_header_cell("Titre"),
                                            rx.table.column_header_cell("Fichier")
                                        )
                                    ),
                                    rx.table.body(
                                        rx.foreach(
                                            DepotsState.selected_scan_ai_findings,
                                            lambda finding: rx.table.row(
                                                rx.table.cell(
                                                    rx.badge(finding.severity, color_scheme=finding.severity_color)
                                                ),
                                                rx.table.cell(finding.title),
                                                rx.table.cell(finding.file_path),
                                                class_name="hover:bg-slate-3/60 transition-colors"
                                            )
                                        )
                                    ),
                                    width="100%"
                                ),
                                class_name="max-h-64 overflow-y-auto zs-scrollbox mt-3"
                            )
                        ),
                        width="100%",
                        spacing="2",
                        class_name="mt-6"
                    )
                ),

                rx.hstack(
                    rx.dialog.close(
                        rx.button("Fermer", on_click=DepotsState.close_cves, color_scheme="gray", variant="soft")
                    ),
                    class_name="mt-6 justify-end"
                ),
                class_name="w-[90vw] max-w-[1400px]"
            ),
            open=DepotsState.cve_dialog_open
        ),
        
        width="100%",
        spacing="4",
        on_mount=DepotsState.load_repositories_data
    )
    
    return main_layout(content, "Dépôts & Scans")
