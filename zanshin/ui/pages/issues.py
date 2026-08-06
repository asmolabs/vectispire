"""Issue backlog: the cross-scan view, and the only place a finding can be acted on.

This page is the missing half of the product. Everything before it was
read-only: scans produced findings, findings were displayed, and there was no
way to say "reviewed, not exploitable here" or "accepted, tracked elsewhere".
`Finding.status` existed and stayed "open" forever; `VexDecision` existed and
was never written. See zanshin/services/issue_service.py for the model.
"""
import reflex as rx

from zanshin.container import get_container
from zanshin.models.issue import (
    STATE_OPEN,
    STATE_RESOLVED,
    TRIAGE_AFFECTED,
    TRIAGE_FIXED,
    TRIAGE_NOT_AFFECTED,
    TRIAGE_UNDER_REVIEW,
    VEX_JUSTIFICATIONS,
)
from zanshin.services.audit_log_service import AuditOperation
from zanshin.ui.auth import requires_login
from zanshin.ui.components import empty_state, stat_card
from zanshin.ui.layout import main_layout
from zanshin.ui.state import BaseState
from zanshin.ui.view_models import (
    IssueRow,
    format_datetime,
    format_percent,
    format_score,
    safe_external_url,
    severity_color,
)

# Labels kept next to the vocabulary they describe, so adding a status can't
# leave the UI showing a raw enum value.
TRIAGE_LABELS = {
    TRIAGE_UNDER_REVIEW: "À examiner",
    TRIAGE_AFFECTED: "Affecté",
    TRIAGE_NOT_AFFECTED: "Non affecté",
    TRIAGE_FIXED: "Corrigé",
}
TRIAGE_COLORS = {
    TRIAGE_UNDER_REVIEW: "amber",
    TRIAGE_AFFECTED: "red",
    TRIAGE_NOT_AFFECTED: "blue",
    TRIAGE_FIXED: "green",
}
JUSTIFICATION_LABELS = {
    "component_not_present": "Composant absent du produit livré",
    "vulnerable_code_not_present": "Code vulnérable absent",
    "vulnerable_code_not_in_execute_path": "Code vulnérable jamais exécuté",
    "vulnerable_code_cannot_be_controlled_by_adversary": "Non contrôlable par un attaquant",
    "inline_mitigations_already_exist": "Mitigations déjà en place",
}
TYPE_LABELS = {
    "vulnerability": "Vulnérabilité",
    "secret": "Secret",
    "iac": "IaC",
    "license": "Licence",
    "ai_review": "Revue IA",
}

PAGE_SIZE = 50

STATE_FILTERS = [
    ("open", "Ouverts"),
    ("resolved", "Résolus"),
    ("", "Tous"),
]
SEVERITY_ORDER = ["critical", "high", "medium", "low", "negligible", "unknown"]


class IssuesState(BaseState):
    """Extends `BaseState` for `logged_in`/`user_role` (used by
    `@requires_login`) and `username`, which is recorded as the author of every
    triage decision."""

    issues: list[IssueRow] = []

    # KPI row
    actionable_count: int = 0
    open_count: int = 0
    resolved_count: int = 0
    under_review_count: int = 0
    # Dicts: Recharts' `data` prop demands them (see severity_chart).
    severity_chart_data: list[dict] = []

    # Pagination. The first version of this screen read a hard-coded 500 rows
    # with no total, so a bigger backlog was silently truncated — which reads
    # exactly like "that's all there is".
    total: int = 0
    offset: int = 0

    # Filters
    filter_state: str = STATE_OPEN
    filter_severity: str = ""
    filter_type: str = ""
    filter_triage: str = ""
    search_query: str = ""

    # Triage dialog
    triage_dialog_open: bool = False
    triage_issue_id: int = 0
    triage_issue_label: str = ""
    triage_status: str = TRIAGE_UNDER_REVIEW
    triage_justification: str = ""
    triage_comment: str = ""

    @rx.var
    def page_label(self) -> str:
        """"1–50 sur 429" — the count is the point: a paginated view that hides
        the total is the same trap as a truncated one."""
        if self.total == 0:
            return "Aucun résultat"
        first = self.offset + 1
        last = min(self.offset + PAGE_SIZE, self.total)
        return f"{first}–{last} sur {self.total}"

    @rx.var
    def has_previous(self) -> bool:
        return self.offset > 0

    @rx.var
    def has_next(self) -> bool:
        return self.offset + PAGE_SIZE < self.total

    @rx.var
    def justification_required(self) -> bool:
        """VEX requires a justification for a `not_affected` statement; the form
        mirrors the service-side rule instead of letting the user submit
        something that will be rejected."""
        return self.triage_status == TRIAGE_NOT_AFFECTED

    @requires_login
    def load_issues(self):
        self.set_current_page("Problèmes")
        container = get_container()
        try:
            repository = container.issue_repository
            filters = dict(
                state=self.filter_state or None,
                triage_status=self.filter_triage or None,
                severity=self.filter_severity or None,
                issue_type=self.filter_type or None,
                search=self.search_query or None,
            )
            self.total = repository.count_filtered(**filters)
            # A filter change can leave the offset past the end of the new result
            # set, which would show an empty page with rows available.
            if self.offset >= self.total:
                self.offset = max(0, (max(self.total - 1, 0) // PAGE_SIZE) * PAGE_SIZE)
            rows = repository.find_filtered(limit=PAGE_SIZE, offset=self.offset, **filters)
            self.issues = [self._to_view(issue) for issue in rows]

            counts = repository.count_by_state_and_triage()
            self.actionable_count = counts.get("actionable", 0)
            self.open_count = counts.get("open", 0)
            self.resolved_count = counts.get("resolved", 0)
            self.under_review_count = counts.get(f"triage_{TRIAGE_UNDER_REVIEW}", 0)

            by_severity = repository.count_open_by_severity()
            self.severity_chart_data = [
                {"name": label, "value": by_severity.get(key, 0), "color": color}
                for key, label, color in (
                    ("critical", "Critique", "var(--red-9)"),
                    ("high", "Élevé", "var(--orange-9)"),
                    ("medium", "Moyen", "var(--yellow-9)"),
                    ("low", "Faible", "var(--blue-9)"),
                )
            ]
        except Exception as e:
            yield self.trigger_toast(f"Erreur de chargement : {str(e)}", is_error=True)
        finally:
            container.db.close()

    def _to_view(self, issue) -> IssueRow:
        target = "—"
        if issue.repository is not None:
            target = issue.repository.name or issue.repository.url
        elif issue.container is not None:
            target = issue.container.image_string

        return IssueRow(
            id=issue.id,
            type=TYPE_LABELS.get(issue.type, issue.type),
            identifier=issue.identifier or "—",
            severity=(issue.severity or "unknown").upper(),
            severity_color=severity_color(issue.severity),
            package=f"{issue.package_name or '—'} {issue.package_version or ''}".strip(),
            file_path=issue.file_path or "—",
            target=target,
            state="Ouvert" if issue.state == STATE_OPEN else "Résolu",
            is_open=issue.state == STATE_OPEN,
            triage=TRIAGE_LABELS.get(issue.triage_status, issue.triage_status),
            triage_color=TRIAGE_COLORS.get(issue.triage_status, "gray"),
            triage_comment=issue.triage_comment or "",
            triaged_by=issue.triaged_by or "",
            epss=format_percent(issue.epss_score),
            is_kev=bool(issue.is_kev),
            cvss=format_score(issue.cvss_score),
            fix=(
                issue.fix_versions
                or ("Aucun correctif" if issue.fix_state in ("not-fixed", "wont-fix") else "—")
            ),
            link=safe_external_url(issue.link),
            description=issue.description or "",
            times_seen=issue.times_seen or 1,
            first_seen=format_datetime(issue.first_seen_at, "%d/%m/%Y"),
            last_seen=format_datetime(issue.last_seen_at, "%d/%m/%Y"),
        )

    # --- Filters ---

    def set_filter_state(self, value: str):
        self.offset = 0
        self.filter_state = value
        return IssuesState.load_issues

    def set_filter_severity(self, value: str):
        self.offset = 0
        self.filter_severity = "" if value == "all" else value
        return IssuesState.load_issues

    def set_filter_type(self, value: str):
        self.offset = 0
        self.filter_type = "" if value == "all" else value
        return IssuesState.load_issues

    def set_filter_triage(self, value: str):
        self.offset = 0
        self.filter_triage = "" if value == "all" else value
        return IssuesState.load_issues

    def set_search_query(self, value: str):
        self.offset = 0
        self.search_query = value
        return IssuesState.load_issues

    def next_page(self):
        if self.has_next:
            self.offset += PAGE_SIZE
            return IssuesState.load_issues

    def previous_page(self):
        if self.has_previous:
            self.offset = max(0, self.offset - PAGE_SIZE)
            return IssuesState.load_issues

    # --- Triage ---

    @requires_login
    def open_triage_dialog(self, issue_id: int):
        container = get_container()
        try:
            issue = container.issue_repository.find_by_id(issue_id)
            if not issue:
                yield self.trigger_toast("Problème introuvable", is_error=True)
                return
            self.triage_issue_id = issue.id
            self.triage_issue_label = f"{issue.identifier or issue.type} — {issue.package_name or ''}".strip()
            self.triage_status = issue.triage_status
            self.triage_justification = issue.triage_justification or ""
            self.triage_comment = issue.triage_comment or ""
            self.triage_dialog_open = True
        finally:
            container.db.close()

    def close_triage_dialog(self):
        self.triage_dialog_open = False

    def set_triage_status(self, value: str):
        self.triage_status = value

    def set_triage_justification(self, value: str):
        self.triage_justification = value

    def set_triage_comment(self, value: str):
        self.triage_comment = value

    @requires_login
    def submit_triage(self):
        container = get_container()
        try:
            issue = container.issue_service.triage(
                container.db,
                self.triage_issue_id,
                self.triage_status,
                actor=self.username,
                justification=self.triage_justification or None,
                comment=self.triage_comment or None,
            )
            container.audit_log_service.record(
                AuditOperation.ISSUE_TRIAGED,
                resource_id=str(issue.id),
                description=(
                    f"Problème {issue.identifier or issue.type} classé "
                    f"'{issue.triage_status}'"
                ),
                user_id=self.username,
            )
            self.triage_dialog_open = False
            yield self.trigger_toast("Décision enregistrée")
            yield IssuesState.load_issues
        except ValueError as e:
            # Service-side validation (unknown status, missing VEX
            # justification): the message is written for the operator.
            yield self.trigger_toast(str(e), is_error=True)
        except Exception as e:
            yield self.trigger_toast(f"Erreur d'enregistrement : {str(e)}", is_error=True)
        finally:
            container.db.close()


def filter_bar() -> rx.Component:
    return rx.hstack(
        rx.segmented_control.root(
            *[
                rx.segmented_control.item(label, value=value or "all")
                for value, label in STATE_FILTERS
            ],
            value=rx.cond(IssuesState.filter_state == "", "all", IssuesState.filter_state),
            on_change=lambda v: IssuesState.set_filter_state(rx.cond(v == "all", "", v)),
        ),
        rx.select(
            ["all", *SEVERITY_ORDER],
            value=rx.cond(IssuesState.filter_severity == "", "all", IssuesState.filter_severity),
            on_change=IssuesState.set_filter_severity,
            placeholder="Sévérité",
            width="150px",
        ),
        rx.select(
            ["all", "vulnerability", "secret", "iac", "license", "ai_review"],
            value=rx.cond(IssuesState.filter_type == "", "all", IssuesState.filter_type),
            on_change=IssuesState.set_filter_type,
            placeholder="Type",
            width="150px",
        ),
        rx.select(
            ["all", TRIAGE_UNDER_REVIEW, TRIAGE_AFFECTED, TRIAGE_NOT_AFFECTED, TRIAGE_FIXED],
            value=rx.cond(IssuesState.filter_triage == "", "all", IssuesState.filter_triage),
            on_change=IssuesState.set_filter_triage,
            placeholder="Triage",
            width="160px",
        ),
        rx.spacer(),
        rx.input(
            placeholder="CVE, paquet, fichier...",
            value=IssuesState.search_query,
            on_change=IssuesState.set_search_query,
            width="260px",
        ),
        width="100%",
        align="center",
        spacing="3",
        class_name="flex-wrap gap-2",
    )


def issue_row(issue: rx.Var) -> rx.Component:
    return rx.table.row(
        rx.table.cell(
            rx.vstack(
                rx.hstack(
                    rx.text(issue.identifier, weight="medium"),
                    rx.cond(
                        issue.is_kev,
                        rx.badge("KEV", color_scheme="red", variant="solid", size="1"),
                    ),
                    spacing="2",
                    align="center",
                ),
                rx.text(issue.type, size="1", color="var(--slate-10)"),
                spacing="0",
            )
        ),
        rx.table.cell(rx.badge(issue.severity, color_scheme=issue.severity_color)),
        rx.table.cell(rx.text(issue.cvss, size="2")),
        rx.table.cell(rx.text(issue.epss, size="2")),
        rx.table.cell(
            rx.vstack(
                rx.text(issue.package, size="2"),
                rx.text(issue.file_path, size="1", color="var(--slate-10)"),
                spacing="0",
            )
        ),
        rx.table.cell(rx.text(issue.target, size="2")),
        rx.table.cell(
            rx.vstack(
                rx.text(issue.fix, size="2", weight="medium"),
                rx.cond(
                    issue.link != "",
                    rx.link("Détails", href=issue.link, is_external=True, size="1"),
                ),
                spacing="0",
            )
        ),
        rx.table.cell(
            rx.vstack(
                rx.text("vu ", issue.times_seen, "×", size="2"),
                rx.text(issue.first_seen, size="1", color="var(--slate-10)"),
                spacing="0",
            )
        ),
        rx.table.cell(
            rx.vstack(
                rx.badge(issue.triage, color_scheme=issue.triage_color),
                rx.cond(
                    issue.triaged_by != "",
                    rx.text(issue.triaged_by, size="1", color="var(--slate-10)"),
                ),
                spacing="1",
                align="start",
            )
        ),
        rx.table.cell(
            rx.button(
                rx.icon(tag="gavel", size=14),
                "Trier",
                size="1",
                variant="soft",
                on_click=lambda: IssuesState.open_triage_dialog(issue.id),
            )
        ),
    )


def triage_dialog() -> rx.Component:
    return rx.dialog.root(
        rx.dialog.content(
            rx.dialog.title("Décision de triage"),
            rx.dialog.description(
                IssuesState.triage_issue_label, size="2", color="var(--slate-10)"
            ),
            rx.vstack(
                rx.text("Statut (vocabulaire VEX)", size="2", weight="medium", class_name="mt-4"),
                rx.select(
                    [TRIAGE_UNDER_REVIEW, TRIAGE_AFFECTED, TRIAGE_NOT_AFFECTED, TRIAGE_FIXED],
                    value=IssuesState.triage_status,
                    on_change=IssuesState.set_triage_status,
                    width="100%",
                ),
                rx.cond(
                    IssuesState.justification_required,
                    rx.vstack(
                        rx.text(
                            "Justification (requise pour « non affecté »)",
                            size="2", weight="medium",
                        ),
                        rx.select(
                            list(VEX_JUSTIFICATIONS),
                            value=IssuesState.triage_justification,
                            on_change=IssuesState.set_triage_justification,
                            placeholder="Choisir une justification VEX",
                            width="100%",
                        ),
                        rx.text(
                            "Ces valeurs sont celles du standard VEX, pour qu'un document "
                            "VEX puisse être produit à partir de ces décisions.",
                            size="1", color="var(--slate-10)",
                        ),
                        spacing="1",
                        width="100%",
                    ),
                ),
                rx.text("Commentaire", size="2", weight="medium"),
                rx.text_area(
                    value=IssuesState.triage_comment,
                    on_change=IssuesState.set_triage_comment,
                    placeholder="Contexte de la décision (facultatif mais recommandé)",
                    width="100%",
                ),
                spacing="2",
                width="100%",
            ),
            rx.hstack(
                rx.button("Annuler", variant="soft", color_scheme="gray",
                          on_click=IssuesState.close_triage_dialog),
                rx.button("Enregistrer", color_scheme="cyan", on_click=IssuesState.submit_triage),
                justify="end",
                spacing="3",
                class_name="mt-6 w-full",
            ),
            max_width="520px",
        ),
        open=IssuesState.triage_dialog_open,
    )


def issues_page() -> rx.Component:
    content = rx.vstack(
        rx.text(
            "Chaque problème est suivi d'un scan à l'autre : première détection, "
            "nombre de fois vu, correctif disponible, et décision de triage.",
            size="2", color="var(--slate-10)",
        ),
        rx.hstack(
            stat_card("À traiter", IssuesState.actionable_count, "circle-alert", "red"),
            stat_card("Ouverts", IssuesState.open_count, "folder-open", "amber"),
            stat_card("À examiner", IssuesState.under_review_count, "search", "cyan"),
            stat_card("Résolus", IssuesState.resolved_count, "circle-check", "green"),
            width="100%",
            spacing="4",
            class_name="flex-wrap",
        ),
        filter_bar(),
        rx.cond(
            IssuesState.issues.length() > 0,
            rx.box(
                rx.table.root(
                    rx.table.header(
                        rx.table.row(
                            rx.table.column_header_cell("Problème"),
                            rx.table.column_header_cell("Sévérité"),
                            rx.table.column_header_cell("CVSS"),
                            rx.table.column_header_cell("EPSS"),
                            rx.table.column_header_cell("Composant / fichier"),
                            rx.table.column_header_cell("Cible"),
                            rx.table.column_header_cell("Correctif"),
                            rx.table.column_header_cell("Historique"),
                            rx.table.column_header_cell("Triage"),
                            rx.table.column_header_cell(""),
                        )
                    ),
                    rx.table.body(rx.foreach(IssuesState.issues, issue_row)),
                    variant="surface",
                    width="100%",
                ),
                class_name="w-full overflow-x-auto rounded-xl border border-slate-4",
            ),
            empty_state(
                "shield-check",
                "Aucun problème pour ces filtres",
                "Lancez un scan, ou élargissez les filtres ci-dessus.",
            ),
        ),
        rx.hstack(
            rx.text(IssuesState.page_label, size="2", color="var(--slate-10)"),
            rx.spacer(),
            rx.button(
                rx.icon(tag="chevron-left", size=16), "Précédent",
                on_click=IssuesState.previous_page,
                disabled=~IssuesState.has_previous,
                variant="soft", size="2",
            ),
            rx.button(
                "Suivant", rx.icon(tag="chevron-right", size=16),
                on_click=IssuesState.next_page,
                disabled=~IssuesState.has_next,
                variant="soft", size="2",
            ),
            width="100%",
            align="center",
            spacing="3",
        ),
        triage_dialog(),
        width="100%",
        spacing="5",
        on_mount=IssuesState.load_issues,
    )
    return main_layout(content, "Problèmes")
