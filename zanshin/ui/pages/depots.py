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
    """Manages the Git repositories configuration, planning (interval/cron), and detailed scan history."""
    
    repositories: list[dict[str, str]] = []
    ssh_keys_list: list[dict[str, str]] = []
    
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

    def load_repositories_data(self):
        self.set_current_page("Dépôts / Plannings")
        container = get_container()
        try:
            db_repos = container.repository_repository.find_all()
            self.repositories = []
            for r in db_repos:
                status = "Non scanné"
                findings = 0
                crit = 0
                high = 0
                med = 0
                low = 0
                scans = sorted(r.scans or [], key=lambda s: s.created_at, reverse=True)
                if scans:
                    latest = scans[0]
                    status = latest.status
                    findings = latest.findings_count
                    summary = latest.summary or {}
                    crit = summary.get("critical", 0)
                    high = summary.get("high", 0)
                    med = summary.get("medium", 0)
                    low = summary.get("low", 0)
                
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
                    "low": str(low)
                })
            
            # Load SSH Keys for dropdown selection
            db_keys = container.ssh_key_repository.find_all()
            self.ssh_keys_list = [{"label": k.name, "value": str(k.id)} for k in db_keys]
        except Exception as e:
            yield self.trigger_toast(f"Erreur de chargement : {str(e)}", is_error=True)
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
            
            # Reset
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
            
            self.selected_scan_name = f"Scan #{s.id} (Branche: {s.branch})"
            
            # Parse findings
            cves_data = s.cves or {}
            matches = cves_data.get("matches", [])
            
            parsed_cves = []
            for m in matches:
                vuln = m.get("vulnerability", {})
                art = m.get("artifact", {})
                fix = vuln.get("fix", {})
                
                parsed_cves.append({
                    "id": vuln.get("id", "N/A"),
                    "severity": vuln.get("severity", "N/A").upper(),
                    "component": art.get("name", "N/A"),
                    "version": art.get("version", "N/A"),
                    "description": vuln.get("description", "Pas de description"),
                    "fix_state": fix.get("state", "unknown"),
                    "link": vuln.get("links", [""])[0] if vuln.get("links") else ""
                })
                
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
                                rx.hstack(
                                    rx.tooltip(
                                        rx.button(
                                            rx.icon(tag="shield"),
                                            size="2",
                                            color_scheme="indigo",
                                            variant="soft",
                                            on_click=lambda: DepotsState.trigger_scan(r["id"])
                                        ),
                                        content="Lancer Scan"
                                    ),
                                    rx.tooltip(
                                        rx.button(
                                            rx.icon(tag="settings"),
                                            size="2",
                                            color_scheme="teal",
                                            variant="soft",
                                            on_click=lambda: DepotsState.view_details(r["id"])
                                        ),
                                        content="Planification / Détails"
                                    ),
                                    rx.tooltip(
                                        rx.button(
                                            rx.icon(tag="trash"),
                                            size="2",
                                            color_scheme="red",
                                            variant="soft",
                                            on_click=lambda: DepotsState.delete_repository(r["id"])
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
                                rx.table.cell(scan["created_at"]),
                                rx.table.cell(
                                    rx.tooltip(
                                        rx.button(
                                            rx.icon(tag="eye"),
                                            size="2",
                                            color_scheme="teal",
                                            variant="soft",
                                            on_click=lambda: DepotsState.show_cves(scan["id"])
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
    content = rx.vstack(
        rx.cond(
            DepotsState.is_viewing_details,
            details_layout_view(),
            list_layout_view()
        ),
        
        # CVE details modal dialog (shared)
        rx.dialog.root(
            rx.dialog.content(
                rx.dialog.title(f"Vulnérabilités de {DepotsState.selected_scan_name}"),
                rx.dialog.description("Détails des failles de sécurité identifiées par Grype"),
                
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
                                rx.table.column_header_cell("Fix Status")
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
                                    )
                                )
                            )
                        ),
                        width="100%"
                    ),
                    class_name="mt-6 max-h-96 overflow-y-auto border border-slate-4 rounded-lg"
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
    
    return main_layout(content, "Dépôts / Plannings")
