import reflex as rx
from typing import List, Dict, Any
from datetime import datetime

from zanshin.ui.state import BaseState
from zanshin.ui.layout import main_layout
from zanshin.container import get_container
from zanshin.models.repository import ZanshinRepository
from zanshin.models.container import Container
from zanshin.models.scan import Scan

class DashboardState(BaseState):
    """Handles data loading and aggregation for the Zanshin dashboard."""
    
    # Aggregated metrics
    repo_count: int = 0
    container_count: int = 0
    vuln_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    
    # Data list
    repositories: list[dict[str, str]] = []

    def load_dashboard_data(self):
        """Loads and computes metrics for the dashboard view."""
        self.set_current_page("Tableau de bord")
        
        container = get_container()
        try:
            db = container.db
            
            # Count entities
            repos = db.query(ZanshinRepository).all()
            self.repo_count = len(repos)
            
            containers = db.query(Container).all()
            self.container_count = len(containers)
            
            # Map repositories for display
            self.repositories = []
            for r in repos:
                latest_scan_status = "Non scanné"
                latest_scan_time = "N/A"
                findings = 0
                crit = 0
                high = 0
                med = 0
                low = 0
                
                # Fetch scans ordered by created_at desc
                scans = sorted(r.scans or [], key=lambda s: s.created_at, reverse=True)
                if scans:
                    latest = scans[0]
                    latest_scan_status = latest.status
                    latest_scan_time = latest.created_at.strftime("%Y-%m-%d %H:%M")
                    findings = latest.findings_count
                    summary = latest.summary or {}
                    crit = summary.get("critical", 0)
                    high = summary.get("high", 0)
                    med = summary.get("medium", 0)
                    low = summary.get("low", 0)
                    
                self.repositories.append({
                    "id": str(r.id),
                    "name": r.name or r.url.split("/")[-1].replace(".git", ""),
                    "url": r.url,
                    "branch": r.branch,
                    "latest_scan_status": latest_scan_status,
                    "latest_scan_time": latest_scan_time,
                    "findings": str(findings),
                    "critical": str(crit),
                    "high": str(high),
                    "medium": str(med),
                    "low": str(low)
                })
                
            # Aggregate vulnerability metrics from latest scans
            total_vulns = 0
            critical = 0
            high = 0
            
            # Get latest scan for each repo and container
            for r in repos:
                scans = sorted(r.scans or [], key=lambda s: s.created_at, reverse=True)
                if scans:
                    latest = scans[0]
                    if latest.summary:
                        total_vulns += latest.summary.get("total", 0)
                        critical += latest.summary.get("critical", 0)
                        high += latest.summary.get("high", 0)
                        
            for c in containers:
                scans = sorted(c.scans or [], key=lambda s: s.created_at, reverse=True)
                if scans:
                    latest = scans[0]
                    if latest.summary:
                        total_vulns += latest.summary.get("total", 0)
                        critical += latest.summary.get("critical", 0)
                        high += latest.summary.get("high", 0)
                        
            self.vuln_count = total_vulns
            self.critical_count = critical
            self.high_count = high
            
        except Exception as e:
            yield self.trigger_toast(f"Erreur lors du chargement des données : {str(e)}", is_error=True)
        finally:
            container.db.close()

def stat_card(title: str, value: str, icon_name: str, color: str = "accent") -> rx.Component:
    """Helper component for stat indicators."""
    return rx.hstack(
        rx.vstack(
            rx.text(title, size="2", color="var(--slate-10)"),
            rx.heading(value, size="7", weight="bold"),
            spacing="1"
        ),
        rx.spacer(),
        rx.center(
            rx.icon(tag=icon_name, size=24, color=f"var(--{color}-9)"),
            class_name=f"p-3 rounded-lg bg-{color}-3"
        ),
        align="center",
        class_name="p-6 rounded-xl bg-slate-2 border border-slate-4 flex-1 shadow-sm"
    )

def dashboard_page() -> rx.Component:
    """Reflex view for dashboard."""
    content = rx.vstack(
        # Welcome heading
        rx.text(
            f"Rapport de sécurité global au {datetime.now().strftime('%d/%m/%Y')}",
            size="2",
            color="var(--slate-10)"
        ),
        
        # Stat cards row
        rx.flex(
            stat_card("Total Dépôts", rx.Var.create(f"{DashboardState.repo_count}"), "git-branch", "blue"),
            stat_card("Images Conteneurs", rx.Var.create(f"{DashboardState.container_count}"), "box", "indigo"),
            stat_card("Vulnerabilités", rx.Var.create(f"{DashboardState.vuln_count}"), "shield-alert", "orange"),
            stat_card("Critiques (CVE)", rx.Var.create(f"{DashboardState.critical_count}"), "triangle-alert", "red"),
            width="100%",
            spacing="4",
            flex_wrap="wrap",
            class_name="mb-6"
        ),
        
        # Repositories overview table
        rx.vstack(
            rx.heading("Dépôts Git surveillés", size="4", weight="bold"),
            
            rx.table.root(
                rx.table.header(
                    rx.table.row(
                        rx.table.column_header_cell("Nom"),
                        rx.table.column_header_cell("URL"),
                        rx.table.column_header_cell("Branche"),
                        rx.table.column_header_cell("Dernier scan"),
                        rx.table.column_header_cell("Statut"),
                        rx.table.column_header_cell("Vulns")
                    )
                ),
                rx.table.body(
                    rx.foreach(
                        DashboardState.repositories,
                        lambda r: rx.table.row(
                            rx.table.row_header_cell(r["name"]),
                            rx.table.cell(r["url"]),
                            rx.table.cell(r["branch"]),
                            rx.table.cell(r["latest_scan_time"]),
                            rx.table.cell(
                                rx.badge(
                                    r["latest_scan_status"],
                                    color_scheme=rx.cond(
                                        r["latest_scan_status"] == "completed",
                                        "green",
                                        rx.cond(r["latest_scan_status"] == "scanning", "blue", "gray")
                                    )
                                )
                            ),
                            rx.table.cell(
                                rx.cond(
                                    (r["findings"] == "0") | (r["latest_scan_status"] == "Non scanné"),
                                    rx.badge("0", color_scheme="green"),
                                    rx.hstack(
                                        rx.cond(r["critical"] != "0", rx.badge(f"Crit: {r['critical']}", color_scheme="red", variant="solid")),
                                        rx.cond(r["high"] != "0", rx.badge(f"Élevé: {r['high']}", color_scheme="orange", variant="solid")),
                                        rx.cond(r["medium"] != "0", rx.badge(f"Moy: {r['medium']}", color_scheme="yellow")),
                                        rx.cond(r["low"] != "0", rx.badge(f"Faible: {r['low']}", color_scheme="blue")),
                                        spacing="1"
                                    )
                                )
                            )
                        )
                    )
                ),
                width="100%"
            ),
            
            width="100%",
            spacing="3",
            class_name="p-6 rounded-xl bg-slate-2 border border-slate-4 shadow-sm"
        ),
        
        width="100%",
        spacing="5",
        on_mount=DashboardState.load_dashboard_data
    )
    
    return main_layout(content, "Tableau de bord")
