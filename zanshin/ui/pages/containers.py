import reflex as rx
import asyncio
from typing import List, Dict, Any
from datetime import datetime

from zanshin.ui.state import BaseState
from zanshin.ui.auth import requires_login
from zanshin.ui.layout import main_layout
from zanshin.ui.components import (
    actionable_badge,
    empty_state,
    severity_badges,
    severity_donut_chart,
    severity_summary,
    stat_card,
    status_badge,
)
from zanshin.ui.view_models import (
    ContainerRow,
    SeverityCounts,
    VulnerabilityRow,
    format_percent,
    format_score,
    safe_external_url,
    severity_chart,
    severity_color,
)
from zanshin.container import get_container
from zanshin.models.container import Container

class ContainersState(BaseState):
    """Manages the Docker containers overview page and CRUD actions."""

    containers: list[ContainerRow] = []

    # Aggregated metrics (latest scan of each container), for the KPI row
    # and severity donut chart above the table.
    total_vulns: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    # Dicts: Recharts' `data` prop demands them (see severity_chart).
    severity_chart_data: list[dict[str, Any]] = []

    dialog_open: bool = False
    new_image_name: str = ""
    new_tag: str = "latest"
    new_registry: str = ""
    new_scan_interval: int = 1440  # 24 hours default

    # CVE details modal state variables
    details_dialog_open: bool = False
    selected_container_name: str = ""
    selected_scan_cves: list[VulnerabilityRow] = []
    selected_scan_summary: SeverityCounts = SeverityCounts()

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
            totals = SeverityCounts()
            total_vulns = 0
            for c in db_containers:
                latest = latest_scans.get(c.id)
                counts = SeverityCounts.from_summary(latest.summary if latest else None)
                if latest:
                    total_vulns += latest.findings_count
                    totals.critical += counts.critical
                    totals.high += counts.high
                    totals.medium += counts.medium
                    totals.low += counts.low

                self.containers.append(ContainerRow(
                    id=c.id,
                    image_name=c.image_name,
                    tag=c.tag,
                    registry=c.registry or "docker.io",
                    status=latest.status if latest else "Non scanné",
                    vulns=latest.findings_count if latest else 0,
                    counts=counts,
                    open_issues=actionable_counts.get(c.id, 0),
                    interval=c.scan_interval_minutes or 1440,
                ))

            self.total_vulns = total_vulns
            self.critical_count = totals.critical
            self.high_count = totals.high
            self.medium_count = totals.medium
            self.low_count = totals.low
            self.severity_chart_data = severity_chart(totals)
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

            # A summary is all this needs now: the dialog is built from the
            # normalized findings, so the raw blob is never read (and may have
            # been pruned — see RetentionService).
            latest_summary = container_ioc.scan_repository.find_latest_summary_by_container_ids(
                [c.id]
            ).get(c.id)
            if not latest_summary:
                self.selected_scan_cves = []
                self.selected_scan_summary = SeverityCounts()
                yield self.trigger_toast("Aucun scan disponible pour cette image.", is_error=True)
                return

            if latest_summary.status != "completed":
                self.selected_scan_cves = []
                self.selected_scan_summary = SeverityCounts()
                yield self.trigger_toast(f"Dernier scan en statut: {latest_summary.status}", is_error=True)
                return

            # From the normalized findings, not `Scan.cves` — see
            # DepotsState.show_cves and RetentionService for why.
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
                for f in container_ioc.finding_repository.find_all_by_scan_id_and_type(
                    latest_summary.id, "vulnerability"
                )
            ]
            self.selected_scan_summary = SeverityCounts.from_summary(latest_summary.summary)
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
            stat_card("Images surveillées", ContainersState.containers.length().to(str), "box"),
            stat_card("Vulnérabilités", rx.Var.create(f"{ContainersState.total_vulns}"),
                      "shield-alert", "orange", alert=ContainersState.total_vulns > 0),
            stat_card("Critiques", rx.Var.create(f"{ContainersState.critical_count}"),
                      "triangle-alert", "red", alert=ContainersState.critical_count > 0),
            stat_card("Élevées", rx.Var.create(f"{ContainersState.high_count}"),
                      "circle-alert", "amber", alert=ContainersState.high_count > 0),
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
                            rx.table.cell(c.registry),
                            rx.table.row_header_cell(c.image_name),
                            rx.table.cell(c.tag),
                            rx.table.cell(c.interval.to_string()),
                            rx.table.cell(status_badge(c.status)),
                            rx.table.cell(severity_badges(c.counts, c.vulns)),
                            # Outstanding issues (open, not settled by triage) —
                            # the count that shrinks as the team works, unlike
                            # the CVE count on its left.
                            rx.table.cell(actionable_badge(c.open_issues)),
                            rx.table.cell(
                                rx.hstack(
                                    rx.tooltip(
                                        rx.button(
                                            rx.icon(tag="shield"),
                                            size="2",
                                            color_scheme="cyan",
                                            variant="soft",
                                            on_click=lambda: ContainersState.trigger_scan(c.id)
                                        ),
                                        content="Lancer Scan"
                                    ),
                                    rx.tooltip(
                                        rx.button(
                                            rx.icon(tag="eye"),
                                            size="2",
                                            color_scheme="teal",
                                            variant="soft",
                                            on_click=lambda: ContainersState.show_scan_details(c.id)
                                        ),
                                        content="Voir CVEs"
                                    ),
                                    rx.tooltip(
                                        rx.button(
                                            rx.icon(tag="trash"),
                                            size="2",
                                            color_scheme="red",
                                            variant="soft",
                                            on_click=lambda: ContainersState.delete_container(c.id)
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
        # Scan Details Dialog Modal
        rx.dialog.root(
            rx.dialog.content(
                rx.dialog.title(f"Vulnérabilités de {ContainersState.selected_container_name}"),
                rx.dialog.description("Liste détaillée des CVEs identifiées par Grype"),
                
                severity_summary(ContainersState.selected_scan_summary),
                
                # Findings Table
                rx.box(
                    rx.table.root(
                        rx.table.header(
                            rx.table.row(
                                rx.table.column_header_cell("Sévérité"),
                                rx.table.column_header_cell("CVE ID"),
                                rx.table.column_header_cell("Composant"),
                                rx.table.column_header_cell("Version"),
                                rx.table.column_header_cell("CVSS"),
                                rx.table.column_header_cell("EPSS"),
                                rx.table.column_header_cell("KEV"),
                                rx.table.column_header_cell("Correctif")
                            )
                        ),
                        rx.table.body(
                            rx.foreach(
                                ContainersState.selected_scan_cves,
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
                                    rx.table.cell(cve.epss),
                                    rx.table.cell(
                                        rx.cond(
                                            cve.is_kev,
                                            rx.badge("Exploitée activement", color_scheme="red", variant="solid"),
                                            rx.text("—", color="var(--slate-9)")
                                        )
                                    ),
                                    rx.table.cell(
                                        rx.badge(
                                            cve.fix,
                                            color_scheme=rx.cond(cve.fix == "Aucun correctif", "gray", "green"),
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
