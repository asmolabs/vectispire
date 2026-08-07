"""The Qualité overview: where the code debt is concentrated.

**Why this is not a filter on the backlog.** If this page were `/issues?type=quality` it
would not deserve to exist — that is a dropdown, and the dropdown is already there. It
earns its place by ranking on axes the backlog cannot: a quality backlog runs to four
figures, and a paginated list of two thousand rows tells nobody what to do on Monday.
"These eight rules are seventy percent of it" does.

Three axes, because they answer three different questions: *what should we stop doing*
(rule), *what should we clean up* (file), *who should be asked* (repository).

The page also states, in as many words, that none of this can fail a build. Someone
looking at a screen full of red-ish counts will otherwise assume the opposite, and the
first thing they will do is ask for the scanner to be turned off.
"""
import reflex as rx

from zanshin.container import get_container
from zanshin.models.issue import Issue
from zanshin.services.sast_service import FINDING_TYPE_QUALITY
from zanshin.ui.auth import requires_login
from zanshin.ui.components import empty_state, stat_card
from zanshin.ui.layout import main_layout
from zanshin.ui.state import BaseState
from zanshin.ui.view_models import TallyRow

TOP_N = 8


class QualiteState(BaseState):
    open_count: int = 0
    rule_count: int = 0
    file_count: int = 0
    top_rules: list[TallyRow] = []
    top_files: list[TallyRow] = []
    top_repositories: list[TallyRow] = []

    @requires_login
    def load_quality(self):
        self.set_current_page("Qualité")
        container = get_container()
        try:
            repository = container.issue_repository
            self.open_count = repository.count_filtered(
                state="open", issue_type=FINDING_TYPE_QUALITY
            )

            rules = repository.count_open_grouped(Issue.identifier, FINDING_TYPE_QUALITY, TOP_N)
            files = repository.count_open_grouped(Issue.file_path, FINDING_TYPE_QUALITY, TOP_N)
            repositories = repository.count_open_grouped(
                Issue.repo_id, FINDING_TYPE_QUALITY, TOP_N
            )

            self.rule_count = len(rules)
            self.file_count = len(files)
            self.top_rules = _tally(rules, self.open_count, "/issues?type=quality")
            self.top_files = _tally(files, self.open_count, "/issues?type=quality")

            names = {
                repo.id: (repo.name or repo.url)
                for repo in container.repository_repository.find_all()
            }
            self.top_repositories = _tally(
                [(names.get(repo_id, f"dépôt #{repo_id}"), count) for repo_id, count in repositories],
                self.open_count,
                "/issues?type=quality",
            )
        except Exception as e:
            yield self.trigger_toast(f"Erreur de chargement : {str(e)}", is_error=True)
        finally:
            container.db.close()


def _tally(rows, total: int, href: str) -> list[TallyRow]:
    """Rows plus their share of the total, computed here rather than in the template.

    Same convention as every other view model in this application: the browser receives
    finished values, not arithmetic."""
    return [
        TallyRow(
            label=str(label) if label not in (None, "") else "(non précisé)",
            count=count,
            share=round(100.0 * count / total, 1) if total else 0.0,
            href=href,
        )
        for label, count in rows
    ]


def _tally_card(title: str, subtitle: str, icon: str, rows) -> rx.Component:
    return rx.vstack(
        rx.hstack(
            rx.icon(tag=icon, size=16, color="var(--slate-9)"),
            rx.heading(title, size="3", weight="bold"),
            spacing="2",
            align="center",
        ),
        rx.text(subtitle, size="1", color="var(--slate-10)", class_name="mb-2"),
        rx.cond(
            rows.length() > 0,
            rx.vstack(
                rx.foreach(
                    rows,
                    lambda row: rx.vstack(
                        rx.hstack(
                            rx.text(
                                row.label,
                                size="2",
                                class_name="truncate",
                                title=row.label,
                            ),
                            rx.spacer(),
                            rx.text(row.count, size="2", weight="bold"),
                            width="100%",
                            align="center",
                        ),
                        # The bar is the point of the ranking: it makes "these few
                        # account for most of it" visible without reading the numbers.
                        rx.box(
                            rx.box(
                                width=f"{row.share}%",
                                height="4px",
                                class_name="rounded-full bg-blue-9",
                            ),
                            width="100%",
                            height="4px",
                            class_name="rounded-full bg-slate-4",
                        ),
                        spacing="1",
                        width="100%",
                    ),
                ),
                spacing="3",
                width="100%",
            ),
            rx.text("Rien à signaler.", size="2", color="var(--slate-9)"),
        ),
        width="100%",
        align_items="start",
        class_name="zs-card h-full",
    )


def qualite_page() -> rx.Component:
    content = rx.vstack(
        rx.text(
            "Ce que l'analyse du code source signale sans que ce soit une faille : "
            "exceptions avalées, code de débogage oublié, constructions qui vieillissent mal.",
            size="2", color="var(--slate-10)",
        ),
        rx.callout(
            "Ces constats ne font jamais échouer une compilation. Ils vivent dans le "
            "backlog, se trient comme les autres, et n'entrent dans aucun verdict de gate.",
            icon="info",
            color_scheme="blue",
            size="1",
            width="100%",
        ),

        rx.grid(
            # Nothing here is ever alarming — quality findings cannot fail a build, and
            # this row would be lying if it looked urgent.
            stat_card("Constats ouverts", QualiteState.open_count, "list-checks",
                      caption="ne bloquent aucune compilation"),
            stat_card("Règles concernées", QualiteState.rule_count, "scan-text"),
            stat_card("Fichiers touchés", QualiteState.file_count, "file-code"),
            columns="3",
            spacing="4",
            width="100%",
            class_name="grid-cols-1 md:grid-cols-3",
        ),

        rx.cond(
            QualiteState.open_count > 0,
            rx.grid(
                _tally_card(
                    "Règles les plus fréquentes",
                    "Ce qu'il faut cesser de faire — corriger une règle en tête traite des dizaines de lignes.",
                    "scan-text",
                    QualiteState.top_rules,
                ),
                _tally_card(
                    "Fichiers les plus touchés",
                    "Où la dette est concentrée.",
                    "file-code",
                    QualiteState.top_files,
                ),
                _tally_card(
                    "Par dépôt",
                    "Quelle équipe est concernée.",
                    "git-branch",
                    QualiteState.top_repositories,
                ),
                columns="3",
                spacing="4",
                width="100%",
                class_name="grid-cols-1 lg:grid-cols-3",
            ),
            rx.box(
                empty_state(
                    "sparkles",
                    "Aucun constat de qualité",
                    "Activez l'analyse du code source dans les Paramètres, puis relancez un scan.",
                ),
                width="100%",
                class_name="zs-card w-full",
            ),
        ),

        rx.cond(
            QualiteState.open_count > 0,
            rx.link(
                rx.button(
                    "Voir tous les constats de qualité",
                    rx.icon(tag="arrow-right", size=14),
                    variant="soft", color_scheme="blue",
                ),
                href="/issues?type=quality",
            ),
        ),

        width="100%",
        spacing="4",
        on_mount=QualiteState.load_quality,
    )

    return main_layout(content, "Qualité")
