import reflex as rx
from typing import List, Dict, Any
from datetime import datetime
import asyncio

from zanshin.ui.state import BaseState
from zanshin.ui.layout import main_layout
from zanshin.container import get_container
from zanshin.models.repository import ZanshinRepository
from zanshin.models.scan import Scan

class ScanCenterState(BaseState):
    """Manages global scan controls, search filtering, and scan history across all repositories."""
    
    repositories: list[dict[str, str]] = []
    scan_history: list[dict[str, str]] = []
    
    search_repos_query: str = ""
    search_history_query: str = ""

    # CVE details dialog variables
    cve_dialog_open: bool = False
    selected_scan_name: str = ""
    selected_scan_cves: list[dict[str, str]] = []
    selected_scan_summary: dict[str, int] = {}

    def set_search_repos_query(self, val: str):
        self.search_repos_query = val
        return ScanCenterState.load_repos_list(self)

    def set_search_history_query(self, val: str):
        self.search_history_query = val
        return ScanCenterState.load_history_list(self)

    def load_all_data(self):
        self.set_current_page("Centre de scan")
        yield ScanCenterState.load_repos_list(self)
        yield ScanCenterState.load_history_list(self)

    def load_repos_list(self):
        container = get_container()
        try:
            db_repos = container.repository_repository.find_all()
            self.repositories = []
            filter_query = self.search_repos_query.lower()
            
            for r in db_repos:
                name = r.name or r.url
                if filter_query and filter_query not in name.lower() and filter_query not in r.url.lower():
                    continue
                
                self.repositories.append({
                    "id": str(r.id),
                    "name": name,
                    "url": r.url,
                    "branch": r.branch,
                    "auth_type": "SSH" if r.ssh_key_id else "HTTPS"
                })
        except Exception as e:
            yield self.trigger_toast(f"Erreur de chargement des dépôts : {str(e)}", is_error=True)
        finally:
            container.db.close()

    def load_history_list(self):
        container = get_container()
        try:
            db = container.db
            db_scans = db.query(Scan).filter(Scan.repo_id.isnot(None)).all()
            self.scan_history = []
            filter_query = self.search_history_query.lower()
            
            # Sort scans by creation date descending
            db_scans = sorted(db_scans, key=lambda s: s.created_at or datetime.min, reverse=True)
            
            for s in db_scans:
                repo_name = s.repository.name or s.repository.url if s.repository else "N/A"
                status = s.status or "pending"
                branch = s.branch or "main"
                
                if filter_query:
                    if (filter_query not in repo_name.lower() and 
                        filter_query not in branch.lower() and 
                        filter_query not in status.lower()):
                        continue
                
                duration = f"{s.duration_ms // 1000}s" if s.duration_ms else "—"
                summary = s.summary or {}
                
                self.scan_history.append({
                    "id": str(s.id),
                    "repo_id": str(s.repo_id) if s.repo_id else "",
                    "repo_name": repo_name,
                    "branch": branch,
                    "status": status,
                    "findings": str(s.findings_count),
                    "critical": str(summary.get("critical", 0)),
                    "high": str(summary.get("high", 0)),
                    "medium": str(summary.get("medium", 0)),
                    "low": str(summary.get("low", 0)),
                    "duration": duration,
                    "created_at": s.created_at.strftime("%d/%m/%y %H:%M") if s.created_at else ""
                })
        except Exception as e:
            yield self.trigger_toast(f"Erreur de chargement de l'historique : {str(e)}", is_error=True)
        finally:
            container.db.close()

    async def trigger_scan(self, repo_id_str: str):
        container_ioc = get_container()
        try:
            repo_id = int(repo_id_str)
            container_ioc.repository_service.trigger_scan(repo_id)
            yield self.trigger_toast("Scan lancé avec succès")
            await asyncio.sleep(1)
            yield ScanCenterState.load_history_list(self)
        except Exception as e:
            yield self.trigger_toast(f"Erreur de scan : {str(e)}", is_error=True)
        finally:
            container_ioc.db.close()

    async def relaunch_scan(self, repo_id_str: str):
        if not repo_id_str:
            yield self.trigger_toast("Dépôt non associé à ce scan", is_error=True)
            return
        yield ScanCenterState.trigger_scan(self, repo_id_str)

    def delete_scan(self, scan_id_str: str):
        container = get_container()
        try:
            scan_id = int(scan_id_str)
            container.scan_repository.delete_by_id(scan_id)
            yield self.trigger_toast("Enregistrement de scan supprimé")
            yield ScanCenterState.load_history_list(self)
        except Exception as e:
            yield self.trigger_toast(f"Erreur de suppression : {str(e)}", is_error=True)
        finally:
            container.db.close()

    def delete_repository(self, repo_id_str: str):
        container = get_container()
        try:
            repo_id = int(repo_id_str)
            container.repository_repository.delete_by_id(repo_id)
            yield self.trigger_toast("Dépôt supprimé")
            yield ScanCenterState.load_all_data(self)
        except Exception as e:
            yield self.trigger_toast(f"Erreur de suppression : {str(e)}", is_error=True)
        finally:
            container.db.close()

    def show_cves(self, scan_id_str: str):
        container = get_container()
        try:
            scan_id = int(scan_id_str)
            db = container.db
            s = db.query(Scan).filter(Scan.id == scan_id).first()
            if not s:
                return
            
            self.selected_scan_name = f"Scan #{s.id} ({s.repository.name or s.repository.url if s.repository else 'N/A'})"
            
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
            yield self.trigger_toast(f"Erreur de lecture des CVEs : {str(e)}", is_error=True)
        finally:
            container.db.close()

    def close_cves(self):
        self.cve_dialog_open = False

def scan_center_page() -> rx.Component:
    """Scan center core page component."""
    content = rx.vstack(
        # Repositories Section
        rx.vstack(
            rx.hstack(
                rx.heading("Dépôts configurés", size="4", weight="bold"),
                rx.spacer(),
                rx.input(
                    placeholder="Rechercher un dépôt...",
                    value=ScanCenterState.search_repos_query,
                    on_change=ScanCenterState.set_search_repos_query,
                    class_name="max-w-xs"
                ),
                width="100%",
                align="center"
            ),
            rx.box(
                rx.table.root(
                    rx.table.header(
                        rx.table.row(
                            rx.table.column_header_cell("# ID"),
                            rx.table.column_header_cell("Nom / URL"),
                            rx.table.column_header_cell("Clé SSH"),
                            rx.table.column_header_cell("Branche"),
                            rx.table.column_header_cell("Actions")
                        )
                    ),
                    rx.table.body(
                        rx.foreach(
                            ScanCenterState.repositories,
                            lambda r: rx.table.row(
                                rx.table.cell(rx.Var.create(f"#{r['id']}")),
                                rx.table.row_header_cell(r["name"]),
                                rx.table.cell(r["auth_type"]),
                                rx.table.cell(r["branch"]),
                                rx.table.cell(
                                    rx.hstack(
                                        rx.tooltip(
                                            rx.button(
                                                rx.icon(tag="play"),
                                                size="2",
                                                color_scheme="green",
                                                variant="soft",
                                                on_click=lambda: ScanCenterState.trigger_scan(r["id"])
                                            ),
                                            content="Lancer Scan"
                                        ),
                                        rx.tooltip(
                                            rx.button(
                                                rx.icon(tag="trash"),
                                                size="2",
                                                color_scheme="red",
                                                variant="soft",
                                                on_click=lambda: ScanCenterState.delete_repository(r["id"])
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
                class_name="w-full border border-slate-4 rounded-lg overflow-hidden max-h-60 overflow-y-auto"
            ),
            width="100%",
            class_name="p-6 rounded-xl bg-slate-2 border border-slate-4 shadow-sm mb-6"
        ),
        
        # Global Scan History Section
        rx.vstack(
            rx.hstack(
                rx.heading("Historique des scans", size="4", weight="bold"),
                rx.spacer(),
                rx.input(
                    placeholder="Rechercher dans l'historique...",
                    value=ScanCenterState.search_history_query,
                    on_change=ScanCenterState.set_search_history_query,
                    class_name="max-w-xs"
                ),
                width="100%",
                align="center"
            ),
            rx.box(
                rx.table.root(
                    rx.table.header(
                        rx.table.row(
                            rx.table.column_header_cell("# ID"),
                            rx.table.column_header_cell("Dépôt"),
                            rx.table.column_header_cell("Branche"),
                            rx.table.column_header_cell("Statut"),
                            rx.table.column_header_cell("Total Vulns"),
                            rx.table.column_header_cell("Date"),
                            rx.table.column_header_cell("Durée"),
                            rx.table.column_header_cell("Actions")
                        )
                    ),
                    rx.table.body(
                        rx.foreach(
                            ScanCenterState.scan_history,
                            lambda s: rx.table.row(
                                rx.table.cell(rx.Var.create(f"#{s['id']}")),
                                rx.table.row_header_cell(s["repo_name"]),
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
                                rx.table.cell(s["created_at"]),
                                rx.table.cell(s["duration"]),
                                rx.table.cell(
                                    rx.hstack(
                                        rx.tooltip(
                                            rx.button(
                                                rx.icon(tag="eye"),
                                                size="2",
                                                color_scheme="teal",
                                                variant="soft",
                                                on_click=lambda: ScanCenterState.show_cves(s["id"])
                                            ),
                                            content="Voir CVEs"
                                        ),
                                        rx.tooltip(
                                            rx.button(
                                                rx.icon(tag="rotate-cw"),
                                                size="2",
                                                color_scheme="green",
                                                variant="soft",
                                                on_click=lambda: ScanCenterState.relaunch_scan(s["repo_id"])
                                            ),
                                            content="Relancer"
                                        ),
                                        rx.tooltip(
                                            rx.button(
                                                rx.icon(tag="trash"),
                                                size="2",
                                                color_scheme="red",
                                                variant="soft",
                                                on_click=lambda: ScanCenterState.delete_scan(s["id"])
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
                class_name="w-full border border-slate-4 rounded-lg overflow-hidden max-h-96 overflow-y-auto"
            ),
            width="100%",
            class_name="p-6 rounded-xl bg-slate-2 border border-slate-4 shadow-sm"
        ),
        
        # Shared CVE details modal dialog
        rx.dialog.root(
            rx.dialog.content(
                rx.dialog.title(f"Vulnérabilités de {ScanCenterState.selected_scan_name}"),
                rx.dialog.description("Détails des failles de sécurité identifiées par Grype"),
                
                # Severity Summary
                rx.hstack(
                    rx.vstack(
                        rx.text("Critique", size="1", color="var(--red-11)"),
                        rx.heading(ScanCenterState.selected_scan_summary.get("critical", 0).to(str), size="5"),
                        class_name="p-4 rounded-lg bg-red-2 border border-red-4 text-center flex-1"
                    ),
                    rx.vstack(
                        rx.text("Élevé", size="1", color="var(--orange-11)"),
                        rx.heading(ScanCenterState.selected_scan_summary.get("high", 0).to(str), size="5"),
                        class_name="p-4 rounded-lg bg-orange-2 border border-orange-4 text-center flex-1"
                    ),
                    rx.vstack(
                        rx.text("Moyen", size="1", color="var(--yellow-11)"),
                        rx.heading(ScanCenterState.selected_scan_summary.get("medium", 0).to(str), size="5"),
                        class_name="p-4 rounded-lg bg-yellow-2 border border-yellow-4 text-center flex-1"
                    ),
                    rx.vstack(
                        rx.text("Faible", size="1", color="var(--blue-11)"),
                        rx.heading(ScanCenterState.selected_scan_summary.get("low", 0).to(str), size="5"),
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
                                ScanCenterState.selected_scan_cves,
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
                        rx.button("Fermer", on_click=ScanCenterState.close_cves, color_scheme="gray", variant="soft")
                    ),
                    class_name="mt-6 justify-end"
                ),
                class_name="max-w-4xl w-full"
            ),
            open=ScanCenterState.cve_dialog_open
        ),
        
        width="100%",
        spacing="4",
        on_mount=ScanCenterState.load_all_data
    )
    
    return main_layout(content, "Centre de scan")
