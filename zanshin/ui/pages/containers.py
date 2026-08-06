import reflex as rx
import asyncio
from typing import List, Dict, Any
from datetime import datetime

from zanshin.ui.state import BaseState
from zanshin.ui.auth import requires_login
from zanshin.ui.layout import main_layout
from zanshin.ui.components import stat_card, severity_donut_chart, empty_state
from zanshin.container import get_container
from zanshin.models.container import Container

class ContainersState(BaseState):
    """Manages the Docker containers overview page and CRUD actions."""

    containers: list[dict[str, str]] = []

    # Aggregated metrics (latest scan of each container), for the KPI row
    # and severity donut chart above the table.
    total_vulns: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    severity_chart_data: list[dict[str, Any]] = []

    dialog_open: bool = False
    new_image_name: str = ""
    new_tag: str = "latest"
    new_registry: str = ""
    new_scan_interval: int = 1440  # 24 hours default

    # CVE details modal state variables
    details_dialog_open: bool = False
    selected_container_name: str = ""
    selected_scan_cves: list[dict[str, str]] = []
    selected_scan_summary: dict[str, int] = {}

    def set_new_image_name(self, val: str):
        self.new_image_name = val

    def set_new_tag(self, val: str):
        self.new_tag = val

    def set_new_registry(self, val: str):
        self.new_registry = val

    def set_new_scan_interval(self, val: str):
        try:
            self.new_scan_interval = int(val) if val else 1440
        except ValueError:
            self.new_scan_interval = 1440

    @requires_login
    def load_container_data(self):
        self.set_current_page("Conteneurs")

        container = get_container()
        try:
            db = container.db
            db_containers = db.query(Container).all()

            # Column-only summaries: this table shows status and counts, so
            # loading each scan's raw SBOM/CVE blob would be pure waste (see
            # ScanSummary).
            latest_scans = container.scan_repository.find_latest_summary_by_container_ids(
                [c.id for c in db_containers]
            )
            # Outstanding (open, untriaged or affected) issues per image — see
            # IssueService for why this differs from the CVE count.
            actionable_counts = container.issue_repository.count_actionable_by_container_ids(
                [c.id for c in db_containers]
            )

            self.containers = []
            total_vulns = 0
            total_critical = 0
            total_high = 0
            total_medium = 0
            total_low = 0
            for c in db_containers:
                status = "Non scanné"
                vulns = 0
                crit = 0
                high = 0
                med = 0
                low = 0
                latest = latest_scans.get(c.id)
                if latest:
                    status = latest.status
                    vulns = latest.findings_count
                    summary = latest.summary or {}
                    crit = summary.get("critical", 0)
                    high = summary.get("high", 0)
                    med = summary.get("medium", 0)
                    low = summary.get("low", 0)
                    total_vulns += vulns
                    total_critical += crit
                    total_high += high
                    total_medium += med
                    total_low += low

                self.containers.append({
                    "id": str(c.id),
                    "image_name": c.image_name,
                    "tag": c.tag,
                    "registry": c.registry or "docker.io",
                    "status": status,
                    "vulns": str(vulns),
                    "critical": str(crit),
                    "high": str(high),
                    "medium": str(med),
                    "low": str(low),
                    "interval": str(c.scan_interval_minutes or 1440),
                    "open_issues": str(actionable_counts.get(c.id, 0)),
                })

            self.total_vulns = total_vulns
            self.critical_count = total_critical
            self.high_count = total_high
            self.medium_count = total_medium
            self.low_count = total_low
            self.severity_chart_data = [
                {"name": "Critique", "value": total_critical, "color": "var(--red-9)"},
                {"name": "Élevé", "value": total_high, "color": "var(--orange-9)"},
                {"name": "Moyen", "value": total_medium, "color": "var(--yellow-9)"},
                {"name": "Faible", "value": total_low, "color": "var(--blue-9)"},
            ]
        except Exception as e:
            yield self.trigger_toast( f"Erreur lors du chargement : {str(e)}", is_error=True)
        finally:
            container.db.close()

    def toggle_dialog(self):
        self.dialog_open = not self.dialog_open

    @requires_login
    def add_container(self):
        if not self.new_image_name:
            yield self.trigger_toast( "Nom de l'image requis", is_error=True)
            return

        container_ioc = get_container()
        try:
            new_c = Container(
                image_name=self.new_image_name,
                tag=self.new_tag,
                registry=self.new_registry if self.new_registry else None,
                scan_interval_minutes=self.new_scan_interval
            )
            container_ioc.container_repository.save(new_c)
            
            # Reset fields
            self.new_image_name = ""
            self.new_tag = "latest"
            self.new_registry = ""
            self.new_scan_interval = 1440
            self.dialog_open = False
            
            yield self.trigger_toast( "Conteneur ajouté avec succès")
            yield ContainersState.load_container_data(self)
        except Exception as e:
            yield self.trigger_toast( f"Erreur d'ajout : {str(e)}", is_error=True)
        finally:
            container_ioc.db.close()

    @requires_login
    async def trigger_scan(self, container_id: int):
        container_ioc = get_container()
        try:
            container_ioc.container_service.trigger_scan(container_id)
            yield self.trigger_toast( "Scan de conteneur démarré en arrière-plan")
            # Wait a moment and reload data
            await asyncio.sleep(1)
            yield ContainersState.load_container_data(self)
        except Exception as e:
            yield self.trigger_toast( f"Erreur de démarrage du scan : {str(e)}", is_error=True)
        finally:
            container_ioc.db.close()

    @requires_login
    def delete_container(self, container_id: int):
        container_ioc = get_container()
        try:
            container_ioc.container_service.delete_by_id(container_id)
            yield self.trigger_toast( "Conteneur supprimé")
            yield ContainersState.load_container_data(self)
        except Exception as e:
            yield self.trigger_toast( f"Erreur de suppression : {str(e)}", is_error=True)
        finally:
            container_ioc.db.close()

    @requires_login
    def show_scan_details(self, container_id: int):
        container_ioc = get_container()
        try:
            db = container_ioc.db
            c = db.query(Container).filter(Container.id == container_id).first()
            if not c:
                return
            self.selected_container_name = c.image_string

            # Identify the latest scan from a summary first, then load that
            # one scan in full — this dialog is the only place that genuinely
            # needs the raw `cves` blob, and only for a single scan.
            latest_summary = container_ioc.scan_repository.find_latest_summary_by_container_ids(
                [c.id]
            ).get(c.id)
            if not latest_summary:
                self.selected_scan_cves = []
                self.selected_scan_summary = {}
                yield self.trigger_toast("Aucun scan disponible pour cette image.", is_error=True)
                return

            if latest_summary.status != "completed":
                self.selected_scan_cves = []
                self.selected_scan_summary = {}
                yield self.trigger_toast(f"Dernier scan en statut: {latest_summary.status}", is_error=True)
                return

            latest = container_ioc.scan_repository.find_by_id(latest_summary.id)

            # Parse findings
            cves_data = latest.cves or {}
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
            self.selected_scan_summary = latest.summary or {}
            self.details_dialog_open = True
        except Exception as e:
            yield self.trigger_toast(f"Erreur de lecture des CVEs : {str(e)}", is_error=True)
        finally:
            container_ioc.db.close()
            
    def close_details_dialog(self):
        self.details_dialog_open = False

def containers_page() -> rx.Component:
    """Containers list view."""
    content = rx.vstack(
        # Page header controls
        rx.hstack(
            rx.text("Supervisez et lancez l'audit des vulnérabilités de vos images Docker", size="2", color="var(--slate-10)"),
            rx.spacer(),
            # Add container modal dialog trigger
            rx.dialog.root(
                rx.dialog.trigger(
                    rx.button("Ajouter une image", rx.icon(tag="plus"), color_scheme="cyan")
                ),
                rx.dialog.content(
                    rx.dialog.title("Ajouter un conteneur à surveiller"),
                    rx.dialog.description("Entrez les coordonnées de l'image de conteneur à ajouter aux audits."),
                    rx.vstack(
                        rx.vstack(
                            rx.text("Nom de l'image", size="2", weight="bold"),
                            rx.input(placeholder="Ex: library/redis", value=ContainersState.new_image_name, on_change=ContainersState.set_new_image_name, required=True, class_name="w-full"),
                            width="100%", spacing="1"
                        ),
                        rx.vstack(
                            rx.text("Tag", size="2", weight="bold"),
                            rx.input(placeholder="Ex: latest", value=ContainersState.new_tag, on_change=ContainersState.set_new_tag, required=True, class_name="w-full"),
                            width="100%", spacing="1"
                        ),
                        rx.vstack(
                            rx.text("Registre (Optionnel)", size="2", weight="bold"),
                            rx.input(placeholder="Ex: docker.io", value=ContainersState.new_registry, on_change=ContainersState.set_new_registry, class_name="w-full"),
                            width="100%", spacing="1"
                        ),
                        rx.vstack(
                            rx.text("Intervalle de scan (Minutes)", size="2", weight="bold"),
                            rx.input(type="number", value=ContainersState.new_scan_interval.to(str), on_change=ContainersState.set_new_scan_interval, class_name="w-full"),
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
                            rx.button("Enregistrer", on_click=ContainersState.add_container, color_scheme="green")
                        ),
                        spacing="3",
                        class_name="mt-6 justify-end"
                    )
                )
            ),
            width="100%",
            align="center"
        ),

        # KPI cards
        rx.flex(
            stat_card("Images surveillées", ContainersState.containers.length().to(str), "box", "cyan"),
            stat_card("Vulnérabilités", rx.Var.create(f"{ContainersState.total_vulns}"), "shield-alert", "orange"),
            stat_card("Critiques", rx.Var.create(f"{ContainersState.critical_count}"), "triangle-alert", "red"),
            stat_card("Élevées", rx.Var.create(f"{ContainersState.high_count}"), "circle-alert", "amber"),
            width="100%",
            spacing="4",
            flex_wrap="wrap",
            class_name="mb-2"
        ),

        # Severity breakdown
        severity_donut_chart(
            ContainersState.severity_chart_data,
            ContainersState.total_vulns > 0,
            subtitle="Par sévérité, sur le dernier scan de chaque image",
        ),

        # Containers table
        rx.cond(
            ContainersState.containers.length() == 0,
            empty_state(
                "box",
                "Aucun conteneur surveillé pour le moment",
                "Ajoutez une image ci-dessus pour démarrer son audit de sécurité.",
            ),
            rx.box(
            rx.table.root(
                rx.table.header(
                    rx.table.row(
                        rx.table.column_header_cell("Registre"),
                        rx.table.column_header_cell("Image"),
                        rx.table.column_header_cell("Tag"),
                        rx.table.column_header_cell("Intervalle (Min)"),
                        rx.table.column_header_cell("Statut"),
                        rx.table.column_header_cell("CVEs"),
                        rx.table.column_header_cell("À traiter"),
                        rx.table.column_header_cell("Actions")
                    )
                ),
                rx.table.body(
                    rx.foreach(
                        ContainersState.containers,
                        lambda c: rx.table.row(
                            rx.table.cell(c["registry"]),
                            rx.table.row_header_cell(c["image_name"]),
                            rx.table.cell(c["tag"]),
                            rx.table.cell(rx.Var.create(f"{c['interval']}")),
                            rx.table.cell(
                                rx.badge(
                                    c["status"],
                                    color_scheme=rx.cond(
                                        c["status"] == "completed",
                                        "green",
                                        rx.cond(c["status"] == "scanning", "blue", "gray")
                                    )
                                )
                            ),
                            rx.table.cell(
                                rx.cond(
                                    (c["vulns"] == "0") | (c["status"] == "Non scanné"),
                                    rx.badge("0", color_scheme="green"),
                                    rx.hstack(
                                        rx.cond(c["critical"] != "0", rx.badge(f"Crit: {c['critical']}", color_scheme="red", variant="solid")),
                                        rx.cond(c["high"] != "0", rx.badge(f"Élevé: {c['high']}", color_scheme="orange", variant="solid")),
                                        rx.cond(c["medium"] != "0", rx.badge(f"Moy: {c['medium']}", color_scheme="yellow")),
                                        rx.cond(c["low"] != "0", rx.badge(f"Faible: {c['low']}", color_scheme="blue")),
                                        spacing="1"
                                    )
                                )
                            ),
                            # Outstanding issues (open, not settled by triage) —
                            # the count that shrinks as the team works, unlike
                            # the CVE count on its left.
                            rx.table.cell(
                                rx.cond(
                                    c["open_issues"] == "0",
                                    rx.badge("0", color_scheme="green"),
                                    rx.link(
                                        rx.badge(c["open_issues"], color_scheme="amber", variant="solid"),
                                        href="/issues",
                                    ),
                                )
                            ),
                            rx.table.cell(
                                rx.hstack(
                                    rx.tooltip(
                                        rx.button(
                                            rx.icon(tag="shield"),
                                            size="2",
                                            color_scheme="cyan",
                                            variant="soft",
                                            on_click=lambda: ContainersState.trigger_scan(c["id"])
                                        ),
                                        content="Lancer Scan"
                                    ),
                                    rx.tooltip(
                                        rx.button(
                                            rx.icon(tag="eye"),
                                            size="2",
                                            color_scheme="teal",
                                            variant="soft",
                                            on_click=lambda: ContainersState.show_scan_details(c["id"])
                                        ),
                                        content="Voir CVEs"
                                    ),
                                    rx.tooltip(
                                        rx.button(
                                            rx.icon(tag="trash"),
                                            size="2",
                                            color_scheme="red",
                                            variant="soft",
                                            on_click=lambda: ContainersState.delete_container(c["id"])
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
            class_name="p-6 rounded-xl bg-slate-2 border border-slate-4 shadow-sm w-full"
            )
        ),
        # Scan Details Dialog Modal
        rx.dialog.root(
            rx.dialog.content(
                rx.dialog.title(f"Vulnérabilités de {ContainersState.selected_container_name}"),
                rx.dialog.description("Liste détaillée des CVEs identifiées par Grype"),
                
                # Severity Cards
                rx.hstack(
                    rx.vstack(
                        rx.hstack(
                            rx.icon(tag="flame", size=14, color="var(--red-11)"),
                            rx.text("Critique", size="1", color="var(--red-11)"),
                            spacing="1", align="center", justify="center", width="100%"
                        ),
                        rx.heading(ContainersState.selected_scan_summary.get("critical", 0).to(str), size="5"),
                        class_name="p-4 rounded-lg bg-red-2 border border-red-4 text-center flex-1"
                    ),
                    rx.vstack(
                        rx.hstack(
                            rx.icon(tag="triangle-alert", size=14, color="var(--orange-11)"),
                            rx.text("Élevé", size="1", color="var(--orange-11)"),
                            spacing="1", align="center", justify="center", width="100%"
                        ),
                        rx.heading(ContainersState.selected_scan_summary.get("high", 0).to(str), size="5"),
                        class_name="p-4 rounded-lg bg-orange-2 border border-orange-4 text-center flex-1"
                    ),
                    rx.vstack(
                        rx.hstack(
                            rx.icon(tag="circle-alert", size=14, color="var(--yellow-11)"),
                            rx.text("Moyen", size="1", color="var(--yellow-11)"),
                            spacing="1", align="center", justify="center", width="100%"
                        ),
                        rx.heading(ContainersState.selected_scan_summary.get("medium", 0).to(str), size="5"),
                        class_name="p-4 rounded-lg bg-yellow-2 border border-yellow-4 text-center flex-1"
                    ),
                    rx.vstack(
                        rx.hstack(
                            rx.icon(tag="info", size=14, color="var(--blue-11)"),
                            rx.text("Faible", size="1", color="var(--blue-11)"),
                            spacing="1", align="center", justify="center", width="100%"
                        ),
                        rx.heading(ContainersState.selected_scan_summary.get("low", 0).to(str), size="5"),
                        class_name="p-4 rounded-lg bg-blue-2 border border-blue-4 text-center flex-1"
                    ),
                    spacing="3",
                    class_name="w-full mt-4"
                ),
                
                # Findings Table
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
                                ContainersState.selected_scan_cves,
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
                                            rx.link(cve["id"], href=cve["link"], is_external=True, class_name="text-cyan-9 hover:underline"),
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
                                    class_name="hover:bg-slate-3/60 transition-colors"
                                )
                            )
                        ),
                        width="100%"
                    ),
                    class_name="mt-6 max-h-96 overflow-y-auto border border-slate-4 rounded-lg"
                ),
                
                rx.hstack(
                    rx.dialog.close(
                        rx.button("Fermer", on_click=ContainersState.close_details_dialog, color_scheme="gray", variant="soft")
                    ),
                    class_name="mt-6 justify-end"
                ),
                class_name="w-[90vw] max-w-[1400px]"
            ),
            open=ContainersState.details_dialog_open
        ),
        
        width="100%",
        spacing="4",
        on_mount=ContainersState.load_container_data
    )
    
    return main_layout(content, "Supervision des conteneurs")
