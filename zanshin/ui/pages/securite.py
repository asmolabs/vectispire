"""The Sécurité overview: whether each target would pass a build, and why.

This screen exists because the answer was already computed and never shown. Since gate
policies were introduced, `POST /api/v1/gate` has told a pipeline whether a target
passes — and the only way for a person to learn the same thing was to run a build and
watch it fail. `policy_gate`'s own docstring anticipated this page.

The verdicts here are the endpoint's verdicts, obtained by calling the same `evaluate`
with the same resolved policy (see `security_overview`), not by a second implementation
in SQL that would agree today and drift at the first new policy flag.
"""
import reflex as rx

from zanshin.container import get_container
from zanshin.models.gate_policy import TARGET_CONTAINER
from zanshin.services.security_overview import (
    OBSERVATION_IN_PROGRESS,
    OBSERVATION_LAST_SCAN_FAILED,
    OBSERVATION_NEVER_SCANNED,
    build_overview,
)
from zanshin.ui.auth import requires_login
from zanshin.ui.components import empty_state, stat_card
from zanshin.ui.layout import main_layout
from zanshin.ui.state import BaseState
from zanshin.ui.view_models import PostureRow, format_datetime

# What a target's last scan means for how much its verdict is worth. A green badge on a
# target nobody has scanned is the one thing this page must never quietly show.
OBSERVATION_LABELS = {
    OBSERVATION_NEVER_SCANNED: ("Jamais scanné", "amber"),
    OBSERVATION_LAST_SCAN_FAILED: ("Dernier scan en échec", "red"),
    OBSERVATION_IN_PROGRESS: ("Scan en cours", "blue"),
}

RULE_LABELS = {
    "kev": "exploitation active connue",
    "severity": "seuil de sévérité atteint",
}


class SecuriteState(BaseState):
    targets: list[PostureRow] = []
    failing_count: int = 0
    total_count: int = 0
    kev_count: int = 0
    never_scanned_count: int = 0
    last_scan_failed_count: int = 0

    @requires_login
    def load_overview(self):
        self.set_current_page("Sécurité")
        container = get_container()
        try:
            # Five queries, whatever the number of targets. The two traps this avoids are
            # both per-target: resolving a gate policy costs one or two queries each, and
            # loading a target's issues costs another. Thirty repositories would mean
            # ninety queries to render one table.
            repositories = container.repository_repository.find_all()
            containers = container.container_repository.find_all()
            overview = build_overview(
                repositories=repositories,
                containers=containers,
                policies=container.gate_policy_service.active_policies(),
                open_issues=container.issue_repository.find_open_for_gate(),
                latest_scan_by_repository=container.scan_repository
                .find_latest_summary_by_repository_ids([r.id for r in repositories]),
                latest_scan_by_container=container.scan_repository
                .find_latest_summary_by_container_ids([c.id for c in containers]),
            )

            self.targets = [_to_row(target) for target in overview.targets]
            self.failing_count = overview.failing_count
            self.total_count = overview.total_count
            self.kev_count = overview.kev_count
            self.never_scanned_count = overview.never_scanned_count
            self.last_scan_failed_count = overview.last_scan_failed_count
        except Exception as e:
            yield self.trigger_toast(f"Erreur de chargement : {str(e)}", is_error=True)
        finally:
            container.db.close()


def _to_row(target) -> PostureRow:
    label, color = OBSERVATION_LABELS.get(target.observation, ("", "gray"))
    violation = target.verdict.violations[0] if target.verdict.violations else None
    reason = ""
    if violation:
        rule = RULE_LABELS.get(violation.rule, violation.rule)
        reason = f"{len(target.verdict.violations)} problème(s) bloquant(s) — {rule}"

    query = "container_id" if target.kind == TARGET_CONTAINER else "repo_id"
    return PostureRow(
        kind=target.kind,
        target_id=target.target_id,
        name=target.name,
        passed=target.passed,
        verdict_label="Conforme" if target.passed else "Non conforme",
        verdict_color="green" if target.passed else "red",
        reason=reason,
        evaluated=target.verdict.evaluated,
        policy_label=target.policy.description,
        observed=target.observed,
        observation_label=label,
        observation_color=color,
        last_scan_at=format_datetime(target.last_scan_at),
        detail_href=f"/issues?{query}={target.target_id}",
    )


def _verdict_cell(target: PostureRow) -> rx.Component:
    return rx.vstack(
        rx.hstack(
            rx.badge(target.verdict_label, color_scheme=target.verdict_color),
            rx.cond(
                target.observation_label != "",
                rx.badge(
                    target.observation_label,
                    color_scheme=target.observation_color,
                    variant="soft",
                ),
            ),
            spacing="2",
            align="center",
        ),
        rx.cond(
            target.reason != "",
            rx.text(target.reason, size="1", color="var(--slate-10)"),
        ),
        spacing="1",
        align_items="start",
    )


def securite_page() -> rx.Component:
    content = rx.vstack(
        rx.text(
            "Le verdict que renvoie « POST /api/v1/gate » pour chaque cible, calculé "
            "avec la même politique. Les constats de qualité n'y entrent jamais.",
            size="2", color="var(--slate-10)",
        ),

        rx.grid(
            stat_card(
                "Non conformes", SecuriteState.failing_count, "shield-alert", "red",
                caption="bloqueraient une compilation",
                alert=SecuriteState.failing_count > 0,
            ),
            stat_card(
                "Cibles suivies", SecuriteState.total_count, "target",
                caption="dépôts et conteneurs",
            ),
            stat_card(
                "KEV ouverts", SecuriteState.kev_count, "flame", "orange",
                caption="exploitation active connue",
                alert=SecuriteState.kev_count > 0,
            ),
            stat_card(
                "Jamais scannées", SecuriteState.never_scanned_count, "eye-off", "amber",
                caption="verdict sans observation",
                alert=SecuriteState.never_scanned_count > 0,
            ),
            stat_card(
                "Scan en échec", SecuriteState.last_scan_failed_count, "circle-x", "red",
                caption="verdict périmé",
                alert=SecuriteState.last_scan_failed_count > 0,
            ),
            columns="5",
            spacing="4",
            width="100%",
            class_name="grid-cols-2 md:grid-cols-3 lg:grid-cols-5",
        ),

        rx.cond(
            (SecuriteState.never_scanned_count + SecuriteState.last_scan_failed_count) > 0,
            rx.callout(
                "Une cible jamais scannée, ou dont le dernier scan a échoué, n'a pas de "
                "problème connu — ce qui n'est pas la même chose que ne pas en avoir. "
                "Son verdict est celui d'un dossier vide.",
                icon="triangle-alert",
                color_scheme="amber",
                size="1",
                width="100%",
            ),
        ),

        rx.box(
            rx.cond(
                SecuriteState.targets.length() > 0,
                rx.table.root(
                    rx.table.header(
                        rx.table.row(
                            rx.table.column_header_cell("Cible"),
                            rx.table.column_header_cell("Verdict"),
                            rx.table.column_header_cell("Évalués"),
                            rx.table.column_header_cell("Politique appliquée"),
                            rx.table.column_header_cell("Dernier scan"),
                            rx.table.column_header_cell(""),
                        )
                    ),
                    rx.table.body(
                        rx.foreach(
                            SecuriteState.targets,
                            lambda target: rx.table.row(
                                rx.table.row_header_cell(
                                    rx.hstack(
                                        rx.icon(
                                            tag=rx.cond(
                                                target.kind == "container", "box", "git-branch"
                                            ),
                                            size=14,
                                            color="var(--slate-9)",
                                        ),
                                        rx.text(target.name, size="2", weight="medium"),
                                        spacing="2",
                                        align="center",
                                    )
                                ),
                                rx.table.cell(_verdict_cell(target)),
                                rx.table.cell(target.evaluated),
                                rx.table.cell(
                                    rx.text(target.policy_label, size="1", color="var(--slate-10)")
                                ),
                                rx.table.cell(
                                    rx.cond(
                                        target.last_scan_at != "",
                                        target.last_scan_at,
                                        rx.text("—", color="var(--slate-9)"),
                                    )
                                ),
                                rx.table.cell(
                                    rx.link(
                                        rx.button(
                                            "Problèmes", rx.icon(tag="arrow-right", size=14),
                                            size="1", variant="soft", color_scheme="gray",
                                        ),
                                        href=target.detail_href,
                                    )
                                ),
                                class_name="hover:bg-slate-3/60 transition-colors",
                            ),
                        )
                    ),
                    width="100%",
                    class_name="zs-table",
                ),
                empty_state(
                    "shield",
                    "Aucune cible suivie",
                    "Ajoutez un dépôt ou un conteneur pour voir son verdict ici.",
                ),
            ),
            width="100%",
            class_name="zs-card w-full",
        ),

        width="100%",
        spacing="4",
        on_mount=SecuriteState.load_overview,
    )

    return main_layout(content, "Sécurité")
