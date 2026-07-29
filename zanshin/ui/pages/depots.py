import reflex as rx
from typing import List, Dict, Any
from datetime import datetime
import uuid
import asyncio

from zanshin.ui.state import BaseState
from zanshin.ui.layout import main_layout
from zanshin.container import get_container
from zanshin.models.repository import ZanshinRepository
from zanshin.models.scan import Scan

class DepotsState(BaseState):
    """Manages the Git repositories configuration, planning, and unified global scan history."""
    
    repositories: list[dict[str, str]] = []
    ssh_keys_list: list[dict[str, str]] = []
    
    # Global Scan History
    scan_history: list[dict[str, str]] = []
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
    selected_repo_interval: int = 1440
    selected_repo_scans: list[dict[str, str]] = []
    is_viewing_details: bool = False

    # CVE details dialog variables
    cve_dialog_open: bool = False
    selected_scan_name: str = ""
    selected_scan_cves: list[dict[str, str]] = []
    selected_scan_summary: dict[str, int] = {}
    selected_scan_secrets: list[dict[str, str]] = []
    selected_scan_licenses: list[dict[str, str]] = []
    selected_scan_iac: list[dict[str, str]] = []
    selected_scan_ai_review: dict[str, str] = {}
    selected_scan_ai_findings: list[dict[str, str]] = []

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

    def set_search_history_query(self, val: str):
        self.search_history_query = val
        return DepotsState.load_history_list(self)

    def load_repositories_data(self):
        self.set_current_page("Dépôts & Scans")
        yield DepotsState.load_repos_list(self)
        yield DepotsState.load_history_list(self)

    def load_repos_list(self):
        container = get_container()
        try:
            db_repos = container.repository_repository.find_all()

            # Figure out each repo's latest scan first, so secret counts can
            # be fetched in a single grouped query instead of one per repo.
            latest_scans = {}
            for r in db_repos:
                scans = sorted(r.scans or [], key=lambda s: s.created_at, reverse=True)
                if scans:
                    latest_scans[r.id] = scans[0]

            secret_counts = container.finding_repository.count_by_scan_ids_and_type(
                [s.id for s in latest_scans.values()], "secret"
            )

            self.repositories = []
            for r in db_repos:
                status = "Non scanné"
                findings = 0
                crit = 0
                high = 0
                med = 0
                low = 0
                secrets = 0
                latest = latest_scans.get(r.id)
                if latest:
                    status = latest.status
                    findings = latest.findings_count
                    summary = latest.summary or {}
                    crit = summary.get("critical", 0)
                    high = summary.get("high", 0)
                    med = summary.get("medium", 0)
                    low = summary.get("low", 0)
                    secrets = secret_counts.get(latest.id, 0)

                self.repositories.append({
                    "id": str(r.id),
                    "name": r.name or r.url,
                    "url": r.url,
                    "branch": r.branch,
                    "status": status,
                    "findings": str(findings),
                    "critical": str(crit),
                    "high": str(high),
                    "medium": str(med),
                    "low": str(low),
                    "secrets": str(secrets)
                })

            # Load SSH Keys for dropdown selection
            db_keys = container.ssh_key_repository.find_all()
            self.ssh_keys_list = [{"label": k.name, "value": str(k.id)} for k in db_keys]
        except Exception as e:
            yield self.trigger_toast(f"Erreur de chargement : {str(e)}", is_error=True)
        finally:
            container.db.close()

    def load_history_list(self):
        container = get_container()
        try:
            db = container.db
            db_scans = db.query(Scan).all()
            self.scan_history = []
            filter_query = self.search_history_query.lower()
            
            # Sort scans by creation date descending
            db_scans = sorted(db_scans, key=lambda s: s.created_at or datetime.min, reverse=True)

            secret_counts = container.finding_repository.count_by_scan_ids_and_type(
                [s.id for s in db_scans], "secret"
            )

            for s in db_scans:
                target_name = "N/A"
                branch = "—"
                if s.repo_id:
                    target_name = s.repository.name or s.repository.url if s.repository else "Dépôt inconnu"
                    branch = s.branch or "main"
                elif s.container_id:
                    target_name = s.container.image_string if s.container else "Image inconnue"
                
                status = s.status or "pending"
                if filter_query:
                    if (filter_query not in target_name.lower() and 
                        filter_query not in branch.lower() and 
                        filter_query not in status.lower()):
                        continue
                
                duration = f"{s.duration_ms // 1000}s" if s.duration_ms else "—"
                summary = s.summary or {}
                
                self.scan_history.append({
                    "id": str(s.id),
                    "repo_id": str(s.repo_id) if s.repo_id else "",
                    "target_name": target_name,
                    "branch": branch,
                    "status": status,
                    "findings": str(s.findings_count),
                    "critical": str(summary.get("critical", 0)),
                    "high": str(summary.get("high", 0)),
                    "medium": str(summary.get("medium", 0)),
                    "low": str(summary.get("low", 0)),
                    "secrets": str(secret_counts.get(s.id, 0)),
                    "duration": duration,
                    "created_at": s.created_at.strftime("%d/%m/%y %H:%M") if s.created_at else ""
                })
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
            container.repository_repository.save(new_r)
            
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

    async def relaunch_scan(self, repo_id_str: str):
        if not repo_id_str:
            yield self.trigger_toast("Dépôt non associé à ce scan", is_error=True)
            return
        yield DepotsState.trigger_scan(self, int(repo_id_str))

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

    def view_details(self, repo_id: int):
        container = get_container()
        try:
            db = container.db
            r = db.query(ZanshinRepository).filter(ZanshinRepository.id == repo_id).first()
            if not r:
                return
            
            self.selected_repo_id = r.id
            self.selected_repo_name = r.name or ""
            self.selected_repo_url = r.url
            self.selected_repo_branch = r.branch
            self.selected_repo_cron = r.scan_cron or ""
            self.selected_repo_interval = r.scan_interval_minutes or 1440
            
            # Load scans list
            self.selected_repo_scans = []
            scans = sorted(r.scans or [], key=lambda s: s.created_at, reverse=True)
            secret_counts = container.finding_repository.count_by_scan_ids_and_type(
                [s.id for s in scans], "secret"
            )
            for s in scans:
                summary = s.summary or {}
                self.selected_repo_scans.append({
                    "id": str(s.id),
                    "branch": s.branch,
                    "status": s.status,
                    "findings": str(s.findings_count),
                    "critical": str(summary.get("critical", 0)),
                    "high": str(summary.get("high", 0)),
                    "medium": str(summary.get("medium", 0)),
                    "low": str(summary.get("low", 0)),
                    "secrets": str(secret_counts.get(s.id, 0)),
                    "created_at": s.created_at.strftime("%d/%m/%Y %H:%M") if s.created_at else ""
                })
            
            self.is_viewing_details = True
        except Exception as e:
            yield self.trigger_toast(f"Erreur de lecture : {str(e)}", is_error=True)
        finally:
            container.db.close()

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
            db.commit()
            
            yield self.trigger_toast("Configuration enregistrée")
            yield DepotsState.load_repositories_data(self)
        except Exception as e:
            yield self.trigger_toast(f"Erreur d'enregistrement : {str(e)}", is_error=True)
        finally:
            container.db.close()

    def exit_details(self):
        self.is_viewing_details = False

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
                target_info = s.container.image_string
                
            self.selected_scan_name = f"Scan #{s.id} ({target_info})"
            
            cves_data = s.cves or {}
            matches = cves_data.get("matches", [])

            # EPSS/CISA-KEV enrichment lives on the normalized `Finding` rows,
            # not in the raw Grype blob — look it up by CVE id (see
            # EnrichmentService / ADR-001 section 6).
            vuln_findings_by_cve = {
                f.identifier: f
                for f in container.finding_repository.find_all_by_scan_id_and_type(scan_id, "vulnerability")
                if f.identifier
            }

            parsed_cves = []
            for m in matches:
                vuln = m.get("vulnerability", {})
                art = m.get("artifact", {})
                fix = vuln.get("fix", {})
                cve_id = vuln.get("id", "N/A")
                finding = vuln_findings_by_cve.get(cve_id)

                parsed_cves.append({
                    "id": cve_id,
                    "severity": vuln.get("severity", "N/A").upper(),
                    "component": art.get("name", "N/A"),
                    "version": art.get("version", "N/A"),
                    "description": vuln.get("description", "Pas de description"),
                    "fix_state": fix.get("state", "unknown"),
                    "link": vuln.get("links", [""])[0] if vuln.get("links") else "",
                    "epss": f"{finding.epss_score:.1%}" if finding and finding.epss_score is not None else "—",
                    "is_kev": "true" if (finding and finding.is_kev) else "false"
                })
                
            secret_findings = container.finding_repository.find_all_by_scan_id_and_type(scan_id, "secret")
            self.selected_scan_secrets = [
                {
                    "rule": f.identifier or "N/A",
                    "file_path": f.file_path or "N/A",
                }
                for f in secret_findings
            ]

            license_findings = container.finding_repository.find_all_by_scan_id_and_type(scan_id, "license")
            self.selected_scan_licenses = [
                {
                    "license": f.identifier or "N/A",
                    "component": f"{f.package_name or 'N/A'} {f.package_version or ''}".strip(),
                }
                for f in license_findings
            ]

            iac_findings = container.finding_repository.find_all_by_scan_id_and_type(scan_id, "iac")
            self.selected_scan_iac = [
                {
                    "severity": (f.severity or "medium").upper(),
                    "check_id": f.identifier or "N/A",
                    "resource": f.package_name or "N/A",
                    "file_path": f.file_path or "N/A",
                }
                for f in iac_findings
            ]

            # Optional AI code review (Ollama, see ADR-001 Phase 8) — at
            # most one row per scan, absent unless the feature was enabled
            # when this scan ran.
            ai_review = container.ai_review_result_repository.find_by_scan_id(scan_id)
            self.selected_scan_ai_review = {
                "model": ai_review.model,
                "status": ai_review.status,
                "response": ai_review.response or "",
                "error": ai_review.error or "",
            } if ai_review else {}

            # Normalized findings extracted from the AI review response (see
            # AiReviewService.parse_findings / ScanProcessor._run_ai_review)
            # — severity/title/file only, the fuller narrative stays above.
            ai_findings = container.finding_repository.find_all_by_scan_id_and_type(scan_id, "ai_review")
            self.selected_scan_ai_findings = [
                {
                    "severity": (f.severity or "unknown").upper(),
                    "title": f.identifier or "N/A",
                    "file_path": f.file_path or "—",
                }
                for f in ai_findings
            ]

            self.selected_scan_cves = parsed_cves
            self.selected_scan_summary = s.summary or {}
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
                    rx.button("Ajouter un dépôt", rx.icon(tag="plus"), color_scheme="indigo")
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
                        rx.table.column_header_cell("Actions")
                    )
                ),
                rx.table.body(
                    rx.foreach(
                        DepotsState.repositories,
                        lambda r: rx.table.row(
                            rx.table.row_header_cell(r["name"]),
                            rx.table.cell(r["url"]),
                            rx.table.cell(r["branch"]),
                            rx.table.cell(
                                rx.badge(
                                    r["status"],
                                    color_scheme=rx.cond(
                                        r["status"] == "completed",
                                        "green",
                                        rx.cond(r["status"] == "scanning", "blue", "gray")
                                    )
                                )
                            ),
                            rx.table.cell(
                                rx.cond(
                                    (r["findings"] == "0") | (r["status"] == "Non scanné"),
                                    rx.badge("0", color_scheme="green"),
                                    rx.hstack(
                                        rx.cond(r["critical"] != "0", rx.badge(f"Crit: {r['critical']}", color_scheme="red", variant="solid")),
                                        rx.cond(r["high"] != "0", rx.badge(f"Élevé: {r['high']}", color_scheme="orange", variant="solid")),
                                        rx.cond(r["medium"] != "0", rx.badge(f"Moy: {r['medium']}", color_scheme="yellow")),
                                        rx.cond(r["low"] != "0", rx.badge(f"Faible: {r['low']}", color_scheme="blue")),
                                        spacing="1"
                                    )
                                )
                            ),
                            rx.table.cell(
                                rx.cond(
                                    r["secrets"] == "0",
                                    rx.badge("0", color_scheme="green"),
                                    rx.badge(f"{r['secrets']} secret(s)", color_scheme="red", variant="solid")
                                )
                            ),
                            rx.table.cell(
                                rx.hstack(
                                    rx.tooltip(
                                        rx.button(
                                            rx.icon(tag="play"),
                                            size="2",
                                            color_scheme="green",
                                            variant="soft",
                                            on_click=lambda: DepotsState.trigger_scan(r["id"].to(int))
                                        ),
                                        content="Lancer Scan"
                                    ),
                                    rx.tooltip(
                                        rx.button(
                                            rx.icon(tag="settings"),
                                            size="2",
                                            color_scheme="teal",
                                            variant="soft",
                                            on_click=lambda: DepotsState.view_details(r["id"].to(int))
                                        ),
                                        content="Planification / Détails"
                                    ),
                                    rx.tooltip(
                                        rx.button(
                                            rx.icon(tag="trash"),
                                            size="2",
                                            color_scheme="red",
                                            variant="soft",
                                            on_click=lambda: DepotsState.delete_repository(r["id"].to(int))
                                        ),
                                        content="Supprimer"
                                    ),
                                    spacing="2"
                                )
                            )
                        )
                    )
                ),
                width="100%"
            ),
            width="100%",
            class_name="p-6 rounded-xl bg-slate-2 border border-slate-4 shadow-sm w-full"
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
                        rx.table.column_header_cell("Date de scan"),
                        rx.table.column_header_cell("Actions")
                    )
                ),
                rx.table.body(
                    rx.foreach(
                        DepotsState.scan_history,
                        lambda s: rx.table.row(
                            rx.table.cell(rx.Var.create(f"#{s['id']}")),
                            rx.table.row_header_cell(s["target_name"]),
                            rx.table.cell(s["branch"]),
                            rx.table.cell(
                                rx.badge(
                                    s["status"],
                                    color_scheme=rx.cond(
                                        s["status"] == "completed",
                                        "green",
                                        rx.cond(s["status"] == "scanning", "blue", "gray")
                                    )
                                )
                            ),
                            rx.table.cell(s["duration"]),
                            rx.table.cell(
                                rx.cond(
                                    (s["findings"] == "0") | (s["status"] == "Non scanné"),
                                    rx.badge("0", color_scheme="green"),
                                    rx.hstack(
                                        rx.cond(s["critical"] != "0", rx.badge(f"Crit: {s['critical']}", color_scheme="red", variant="solid")),
                                        rx.cond(s["high"] != "0", rx.badge(f"Élevé: {s['high']}", color_scheme="orange", variant="solid")),
                                        rx.cond(s["medium"] != "0", rx.badge(f"Moy: {s['medium']}", color_scheme="yellow")),
                                        rx.cond(s["low"] != "0", rx.badge(f"Faible: {s['low']}", color_scheme="blue")),
                                        spacing="1"
                                    )
                                )
                            ),
                            rx.table.cell(
                                rx.cond(
                                    s["secrets"] == "0",
                                    rx.badge("0", color_scheme="green"),
                                    rx.badge(f"{s['secrets']} secret(s)", color_scheme="red", variant="solid")
                                )
                            ),
                            rx.table.cell(s["created_at"]),
                            rx.table.cell(
                                rx.hstack(
                                    rx.tooltip(
                                        rx.button(
                                            rx.icon(tag="eye"),
                                            size="2",
                                            color_scheme="teal",
                                            variant="soft",
                                            on_click=lambda: DepotsState.show_cves(s["id"].to(int))
                                        ),
                                        content="Détails (CVEs & secrets)"
                                    ),
                                    rx.cond(
                                        s["repo_id"] != "",
                                        rx.tooltip(
                                            rx.button(
                                                rx.icon(tag="refresh-cw"),
                                                size="2",
                                                color_scheme="green",
                                                variant="soft",
                                                on_click=lambda: DepotsState.relaunch_scan(s["repo_id"])
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
                                            on_click=lambda: DepotsState.delete_scan(s["id"])
                                        ),
                                        content="Supprimer"
                                    ),
                                    spacing="2"
                                )
                            )
                        )
                    )
                ),
                width="100%"
            ),
            width="100%",
            class_name="p-6 rounded-xl bg-slate-2 border border-slate-4 shadow-sm w-full"
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
                    rx.input(value=DepotsState.selected_repo_cron, on_change=DepotsState.set_selected_repo_cron, class_name="w-full"),
                    width="30%"
                ),
                rx.button("Enregistrer", on_click=DepotsState.save_config, color_scheme="indigo", class_name="self-end mb-1"),
                align="center",
                spacing="4",
                width="100%"
            ),
            width="100%",
            class_name="p-6 rounded-xl bg-slate-2 border border-slate-4 shadow-sm mb-6"
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
                            rx.table.column_header_cell("Date de début"),
                            rx.table.column_header_cell("Actions")
                        )
                    ),
                    rx.table.body(
                        rx.foreach(
                            DepotsState.selected_repo_scans,
                            lambda scan: rx.table.row(
                                rx.table.cell(rx.Var.create(f"#{scan['id']}")),
                                rx.table.cell(scan["branch"]),
                                rx.table.cell(
                                    rx.badge(
                                        scan["status"],
                                        color_scheme=rx.cond(
                                            scan["status"] == "completed",
                                            "green",
                                            rx.cond(scan["status"] == "scanning", "blue", "gray")
                                        )
                                    )
                                ),
                                rx.table.cell(
                                    rx.cond(
                                        (scan["findings"] == "0") | (scan["status"] == "Non scanné"),
                                        rx.badge("0", color_scheme="green"),
                                        rx.hstack(
                                            rx.cond(scan["critical"] != "0", rx.badge(f"Crit: {scan['critical']}", color_scheme="red", variant="solid")),
                                            rx.cond(scan["high"] != "0", rx.badge(f"Élevé: {scan['high']}", color_scheme="orange", variant="solid")),
                                            rx.cond(scan["medium"] != "0", rx.badge(f"Moy: {scan['medium']}", color_scheme="yellow")),
                                            rx.cond(scan["low"] != "0", rx.badge(f"Faible: {scan['low']}", color_scheme="blue")),
                                            spacing="1"
                                        )
                                    )
                                ),
                                rx.table.cell(
                                    rx.cond(
                                        scan["secrets"] == "0",
                                        rx.badge("0", color_scheme="green"),
                                        rx.badge(f"{scan['secrets']} secret(s)", color_scheme="red", variant="solid")
                                    )
                                ),
                                rx.table.cell(scan["created_at"]),
                                rx.table.cell(
                                    rx.tooltip(
                                        rx.button(
                                            rx.icon(tag="eye"),
                                            size="2",
                                            color_scheme="teal",
                                            variant="soft",
                                            on_click=lambda: DepotsState.show_cves(scan["id"].to(int))
                                        ),
                                        content="Voir CVEs"
                                    )
                                )
                            )
                        )
                    ),
                    width="100%"
                ),
                class_name="w-full border border-slate-4 rounded-lg overflow-hidden"
            ),
            width="100%"
        ),
        width="100%"
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
            tabbed_view
        ),
        
        # CVE details modal dialog (shared)
        rx.dialog.root(
            rx.dialog.content(
                rx.dialog.title(f"Vulnérabilités de {DepotsState.selected_scan_name}"),
                rx.dialog.description("Détails des failles, secrets, licences non conformes, et manifestes IaC mal configurés identifiés"),
                
                # Severity Summary
                rx.hstack(
                    rx.vstack(
                        rx.text("Critique", size="1", color="var(--red-11)"),
                        rx.heading(DepotsState.selected_scan_summary.get("critical", 0).to(str), size="5"),
                        class_name="p-4 rounded-lg bg-red-2 border border-red-4 text-center flex-1"
                    ),
                    rx.vstack(
                        rx.text("Élevé", size="1", color="var(--orange-11)"),
                        rx.heading(DepotsState.selected_scan_summary.get("high", 0).to(str), size="5"),
                        class_name="p-4 rounded-lg bg-orange-2 border border-orange-4 text-center flex-1"
                    ),
                    rx.vstack(
                        rx.text("Moyen", size="1", color="var(--yellow-11)"),
                        rx.heading(DepotsState.selected_scan_summary.get("medium", 0).to(str), size="5"),
                        class_name="p-4 rounded-lg bg-yellow-2 border border-yellow-4 text-center flex-1"
                    ),
                    rx.vstack(
                        rx.text("Faible", size="1", color="var(--blue-11)"),
                        rx.heading(DepotsState.selected_scan_summary.get("low", 0).to(str), size="5"),
                        class_name="p-4 rounded-lg bg-blue-2 border border-blue-4 text-center flex-1"
                    ),
                    spacing="3",
                    class_name="w-full mt-4"
                ),
                
                # CVE list table
                rx.box(
                    rx.table.root(
                        rx.table.header(
                            rx.table.row(
                                rx.table.column_header_cell("Sévérité"),
                                rx.table.column_header_cell("CVE ID"),
                                rx.table.column_header_cell("Composant"),
                                rx.table.column_header_cell("Version"),
                                rx.table.column_header_cell("Description"),
                                rx.table.column_header_cell("Fix Status"),
                                rx.table.column_header_cell("EPSS"),
                                rx.table.column_header_cell("KEV")
                            )
                        ),
                        rx.table.body(
                            rx.foreach(
                                DepotsState.selected_scan_cves,
                                lambda cve: rx.table.row(
                                    rx.table.cell(
                                        rx.badge(
                                            cve["severity"],
                                            color_scheme=rx.cond(
                                                cve["severity"] == "CRITICAL",
                                                "red",
                                                rx.cond(
                                                    cve["severity"] == "HIGH",
                                                    "orange",
                                                    rx.cond(
                                                        cve["severity"] == "MEDIUM",
                                                        "yellow",
                                                        "blue"
                                                    )
                                                )
                                            )
                                        )
                                    ),
                                    rx.table.cell(
                                        rx.cond(
                                            cve["link"] != "",
                                            rx.link(cve["id"], href=cve["link"], is_external=True, class_name="text-indigo-9 hover:underline"),
                                            rx.text(cve["id"])
                                        )
                                    ),
                                    rx.table.cell(cve["component"]),
                                    rx.table.cell(cve["version"]),
                                    rx.table.cell(cve["description"]),
                                    rx.table.cell(
                                        rx.badge(
                                            cve["fix_state"],
                                            color_scheme=rx.cond(cve["fix_state"] == "fixed", "green", "gray")
                                        )
                                    ),
                                    rx.table.cell(cve["epss"]),
                                    rx.table.cell(
                                        rx.cond(
                                            cve["is_kev"] == "true",
                                            rx.badge("Exploitée activement", color_scheme="red", variant="solid"),
                                            rx.text("—", color="var(--slate-9)")
                                        )
                                    )
                                )
                            )
                        ),
                        width="100%"
                    ),
                    class_name="mt-6 max-h-96 overflow-y-auto border border-slate-4 rounded-lg"
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
                                            rx.table.cell(rx.badge(leak["rule"], color_scheme="red", variant="solid")),
                                            rx.table.cell(leak["file_path"])
                                        )
                                    )
                                ),
                                width="100%"
                            ),
                            class_name="max-h-64 overflow-y-auto border border-slate-4 rounded-lg"
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
                                            rx.table.cell(rx.badge(lic["license"], color_scheme="orange", variant="solid")),
                                            rx.table.cell(lic["component"])
                                        )
                                    )
                                ),
                                width="100%"
                            ),
                            class_name="max-h-64 overflow-y-auto border border-slate-4 rounded-lg"
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
                                                rx.badge(
                                                    check["severity"],
                                                    color_scheme=rx.cond(
                                                        check["severity"] == "CRITICAL",
                                                        "red",
                                                        rx.cond(
                                                            check["severity"] == "HIGH",
                                                            "orange",
                                                            rx.cond(check["severity"] == "LOW", "blue", "yellow")
                                                        )
                                                    )
                                                )
                                            ),
                                            rx.table.cell(check["check_id"]),
                                            rx.table.cell(check["resource"]),
                                            rx.table.cell(check["file_path"])
                                        )
                                    )
                                ),
                                width="100%"
                            ),
                            class_name="max-h-64 overflow-y-auto border border-slate-4 rounded-lg"
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
                    DepotsState.selected_scan_ai_review.get("model", "") != "",
                    rx.vstack(
                        rx.hstack(
                            rx.heading("Revue de code par IA", size="3", weight="bold"),
                            rx.badge(
                                DepotsState.selected_scan_ai_review.get("model", ""),
                                color_scheme="purple", variant="soft"
                            ),
                            rx.cond(
                                DepotsState.selected_scan_ai_review.get("status", "") == "failed",
                                rx.badge("Échec", color_scheme="red", variant="solid")
                            ),
                            align="center",
                            spacing="2"
                        ),
                        rx.cond(
                            DepotsState.selected_scan_ai_review.get("status", "") == "failed",
                            rx.callout(
                                DepotsState.selected_scan_ai_review.get("error", "Erreur inconnue"),
                                icon="triangle-alert", color_scheme="red", size="1"
                            ),
                            rx.box(
                                rx.text(
                                    DepotsState.selected_scan_ai_review.get("response", ""),
                                    size="2", white_space="pre-wrap"
                                ),
                                class_name="p-4 rounded-lg bg-slate-2 border border-slate-4 max-h-64 overflow-y-auto"
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
                                                    rx.badge(
                                                        finding["severity"],
                                                        color_scheme=rx.cond(
                                                            finding["severity"] == "CRITICAL",
                                                            "red",
                                                            rx.cond(
                                                                finding["severity"] == "HIGH",
                                                                "orange",
                                                                rx.cond(
                                                                    finding["severity"] == "MEDIUM",
                                                                    "yellow",
                                                                    rx.cond(finding["severity"] == "LOW", "blue", "gray")
                                                                )
                                                            )
                                                        )
                                                    )
                                                ),
                                                rx.table.cell(finding["title"]),
                                                rx.table.cell(finding["file_path"])
                                            )
                                        )
                                    ),
                                    width="100%"
                                ),
                                class_name="max-h-64 overflow-y-auto border border-slate-4 rounded-lg mt-3"
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
                class_name="max-w-4xl w-full"
            ),
            open=DepotsState.cve_dialog_open
        ),
        
        width="100%",
        spacing="4",
        on_mount=DepotsState.load_repositories_data
    )
    
    return main_layout(content, "Dépôts & Scans")
