import reflex as rx
from typing import List, Dict, Any
from datetime import datetime, timedelta

from zanshin.ui.state import BaseState
from zanshin.ui.auth import requires_login
from zanshin.ui.layout import main_layout
from zanshin.ui.components import stat_card, severity_donut_chart, empty_state
from zanshin.container import get_container
from zanshin.models.repository import ZanshinRepository
from zanshin.models.container import Container
from zanshin.models.scan import Scan

DAYS_OF_ACTIVITY = 14

class DashboardState(BaseState):
    """Handles data loading and aggregation for the Zanshin dashboard."""

    # Aggregated metrics
    repo_count: int = 0
    container_count: int = 0
    vuln_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    secret_count: int = 0
    last_scan_display: str = "Aucun scan"

    # Data list
    repositories: list[dict[str, str]] = []

    # Chart data
    severity_chart_data: list[dict[str, Any]] = []
    daily_scan_data: list[dict[str, Any]] = []

    @requires_login
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

            # Latest scan per repo, needed both for the table and for the
            # secrets count (one grouped query instead of one per repo, same
            # pattern as depots.py/containers.py).
            latest_repo_scans = container.scan_repository.find_latest_summary_by_repository_ids(
                [r.id for r in repos]
            )

            secret_counts = container.finding_repository.count_by_scan_ids_and_type(
                [s.id for s in latest_repo_scans.values()], "secret"
            )

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
                secrets = 0

                latest = latest_repo_scans.get(r.id)
                if latest:
                    latest_scan_status = latest.status
                    latest_scan_time = latest.created_at.strftime("%d/%m/%Y %H:%M")
                    findings = latest.findings_count
                    summary = latest.summary or {}
                    crit = summary.get("critical", 0)
                    high = summary.get("high", 0)
                    med = summary.get("medium", 0)
                    low = summary.get("low", 0)
                    secrets = secret_counts.get(latest.id, 0)

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
                    "low": str(low),
                    "secrets": str(secrets)
                })

            self.secret_count = sum(secret_counts.values())

            # Aggregate vulnerability metrics from latest scans (repos + containers)
            total_vulns = 0
            critical = 0
            high = 0
            medium = 0
            low = 0
            latest_dates = []

            for latest in latest_repo_scans.values():
                if latest.summary:
                    total_vulns += latest.summary.get("total", 0)
                    critical += latest.summary.get("critical", 0)
                    high += latest.summary.get("high", 0)
                    medium += latest.summary.get("medium", 0)
                    low += latest.summary.get("low", 0)
                if latest.created_at:
                    latest_dates.append(latest.created_at)

            latest_container_scans = container.scan_repository.find_latest_summary_by_container_ids(
                [c.id for c in containers]
            )
            for latest in latest_container_scans.values():
                if latest.summary:
                    total_vulns += latest.summary.get("total", 0)
                    critical += latest.summary.get("critical", 0)
                    high += latest.summary.get("high", 0)
                    medium += latest.summary.get("medium", 0)
                    low += latest.summary.get("low", 0)
                if latest.created_at:
                    latest_dates.append(latest.created_at)

            self.vuln_count = total_vulns
            self.critical_count = critical
            self.high_count = high
            self.medium_count = medium
            self.low_count = low

            self.last_scan_display = max(latest_dates).strftime("%d/%m/%Y %H:%M") if latest_dates else "Aucun scan"

            self.severity_chart_data = [
                {"name": "Critique", "value": critical, "color": "var(--red-9)"},
                {"name": "Élevé", "value": high, "color": "var(--orange-9)"},
                {"name": "Moyen", "value": medium, "color": "var(--yellow-9)"},
                {"name": "Faible", "value": low, "color": "var(--blue-9)"},
            ]

            # Scan activity over the last DAYS_OF_ACTIVITY days, across
            # repos and containers alike — a simple day-bucketed count,
            # not a vulnerability trend (summaries aren't retained
            # historically beyond each scan's own row).
            today = datetime.now().date()
            day_buckets = {
                (today - timedelta(days=i)): 0
                for i in range(DAYS_OF_ACTIVITY - 1, -1, -1)
            }
            cutoff = today - timedelta(days=DAYS_OF_ACTIVITY - 1)
            for created_at in container.scan_repository.find_all_created_at():
                scan_day = created_at.date()
                if scan_day >= cutoff:
                    day_buckets[scan_day] = day_buckets.get(scan_day, 0) + 1

            self.daily_scan_data = [
                {"day": day.strftime("%d/%m"), "scans": count}
                for day, count in day_buckets.items()
            ]

        except Exception as e:
            yield self.trigger_toast(f"Erreur lors du chargement des données : {str(e)}", is_error=True)
        finally:
            container.db.close()

def activity_chart() -> rx.Component:
    """Bar chart of the number of scans run per day, over the last two
    weeks — a simple activity/adoption signal, not a vulnerability trend."""
    return rx.vstack(
        rx.heading("Activité de scan", size="3", weight="bold"),
        rx.text(
            f"Nombre de scans lancés par jour, {DAYS_OF_ACTIVITY} derniers jours",
            size="1", color="var(--slate-10)", class_name="mb-2"
        ),
        rx.recharts.bar_chart(
            rx.recharts.cartesian_grid(stroke_dasharray="3 3", opacity=0.2),
            rx.recharts.x_axis(data_key="day", font_size=11),
            rx.recharts.y_axis(allow_decimals=False, font_size=11),
            rx.recharts.graphing_tooltip(),
            rx.recharts.bar(data_key="scans", fill="var(--accent-9)", radius=[6, 6, 0, 0]),
            data=DashboardState.daily_scan_data,
            width="100%",
            height=260,
        ),
        width="100%",
        spacing="1",
        class_name="p-6 rounded-xl bg-slate-2 border border-slate-4 shadow-sm flex-1"
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
            stat_card("Dépôts", rx.Var.create(f"{DashboardState.repo_count}"), "git-branch", "blue"),
            stat_card("Conteneurs", rx.Var.create(f"{DashboardState.container_count}"), "box", "cyan"),
            stat_card("Vulnérabilités", rx.Var.create(f"{DashboardState.vuln_count}"), "shield-alert", "orange"),
            stat_card("Critiques", rx.Var.create(f"{DashboardState.critical_count}"), "triangle-alert", "red"),
            stat_card("Secrets", rx.Var.create(f"{DashboardState.secret_count}"), "key-round", "amber"),
            stat_card("Dernier scan", DashboardState.last_scan_display, "clock", "teal"),
            width="100%",
            spacing="4",
            flex_wrap="wrap",
            class_name="mb-6"
        ),

        # Charts row
        rx.flex(
            severity_donut_chart(
                DashboardState.severity_chart_data,
                DashboardState.vuln_count > 0,
                subtitle="Par sévérité, sur le dernier scan de chaque dépôt et conteneur",
            ),
            activity_chart(),
            width="100%",
            spacing="4",
            flex_wrap="wrap",
            class_name="mb-6"
        ),

        # Repositories overview table
        rx.vstack(
            rx.heading("Dépôts Git surveillés", size="4", weight="bold"),

            rx.cond(
                DashboardState.repositories.length() == 0,
                empty_state(
                    "git-branch",
                    "Aucun dépôt configuré pour le moment",
                    "Ajoutez-en un depuis la page Dépôts & Scans.",
                ),
                rx.table.root(
                    rx.table.header(
                        rx.table.row(
                            rx.table.column_header_cell("Nom"),
                            rx.table.column_header_cell("URL"),
                            rx.table.column_header_cell("Branche"),
                            rx.table.column_header_cell("Dernier scan"),
                            rx.table.column_header_cell("Statut"),
                            rx.table.column_header_cell("Secrets"),
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
                                        r["secrets"] == "0",
                                        rx.badge("0", color_scheme="green"),
                                        rx.badge(f"{r['secrets']} secret(s)", color_scheme="red", variant="solid")
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
                                ),
                                class_name="hover:bg-slate-3/60 transition-colors"
                            )
                        )
                    ),
                    width="100%"
                )
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
