import reflex as rx

def stat_card(title: str, value, icon_name: str, color: str = "accent") -> rx.Component:
    """Shared KPI card used across the dashboard, containers, and dépôts
    pages — a title/value pair with a colored icon badge, and a subtle
    hover highlight matching the card's color."""
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
        class_name=(
            f"p-6 rounded-xl bg-slate-2 border border-slate-4 flex-1 shadow-sm "
            f"hover:border-{color}-7 hover:shadow-md transition-all min-w-[200px]"
        )
    )

def severity_donut_chart(
    data,
    has_data,
    title: str = "Répartition des vulnérabilités",
    subtitle: str = "Par sévérité, sur le dernier scan de chaque cible",
) -> rx.Component:
    """Shared severity breakdown donut (Critique/Élevé/Moyen/Faible),
    with a friendly empty state when `has_data` is falsy. `data` must be a
    Var resolving to a list of `{"name", "value", "color"}` dicts."""
    return rx.vstack(
        rx.heading(title, size="3", weight="bold"),
        rx.text(subtitle, size="1", color="var(--slate-10)", class_name="mb-2"),
        rx.cond(
            has_data,
            rx.recharts.pie_chart(
                rx.recharts.pie(
                    rx.foreach(
                        data,
                        lambda item: rx.recharts.cell(fill=item["color"])
                    ),
                    data=data,
                    data_key="value",
                    name_key="name",
                    cx="50%",
                    cy="50%",
                    inner_radius=55,
                    outer_radius=85,
                    padding_angle=3,
                ),
                rx.recharts.graphing_tooltip(),
                rx.recharts.legend(),
                width="100%",
                height=260,
            ),
            rx.center(
                rx.vstack(
                    rx.icon(tag="shield-check", size=36, color="var(--green-9)"),
                    rx.text("Aucune vulnérabilité ouverte détectée", size="2", color="var(--slate-10)"),
                    spacing="2", align="center"
                ),
                class_name="w-full h-[260px]"
            )
        ),
        width="100%",
        spacing="1",
        class_name="p-6 rounded-xl bg-slate-2 border border-slate-4 shadow-sm flex-1"
    )

def empty_state(icon_name: str, title: str, subtitle: str) -> rx.Component:
    """Shared friendly empty-state block for tables with no rows yet."""
    return rx.center(
        rx.vstack(
            rx.icon(tag=icon_name, size=40, color="var(--slate-8)"),
            rx.text(title, size="3", weight="medium", color="var(--slate-11)"),
            rx.text(subtitle, size="2", color="var(--slate-9)"),
            spacing="2",
            align="center"
        ),
        class_name="w-full py-16 rounded-xl bg-slate-2 border border-dashed border-slate-5"
    )


# --- Shared row badges -------------------------------------------------------
#
# These were copy-pasted inline in every table, with the string comparisons that
# the `dict[str, str]` rows forced (`rx.cond(r["critical"] != "0", ...)`). Now
# that rows are typed (see zanshin/ui/view_models.py), the comparisons are
# numeric and the markup lives in one place — three tables in depots.py alone had
# drifted apart on colours and wording.

def status_badge(status) -> rx.Component:
    """Scan status, coloured the same way everywhere."""
    return rx.badge(
        status,
        color_scheme=rx.cond(
            status == "completed",
            "green",
            rx.cond(status == "scanning", "blue", rx.cond(status == "failed", "red", "gray")),
        ),
    )


def severity_badges(counts, findings) -> rx.Component:
    """The Crit/Élevé/Moy/Faible cluster, or a green zero.

    `findings == 0` is a real numeric test now; it used to be `r["findings"] ==
    "0"`, which silently did nothing the day a builder wrote an int.
    """
    return rx.cond(
        findings == 0,
        rx.badge("0", color_scheme="green"),
        rx.hstack(
            rx.cond(counts.critical > 0, rx.badge(f"Crit: {counts.critical}", color_scheme="red", variant="solid")),
            rx.cond(counts.high > 0, rx.badge(f"Élevé: {counts.high}", color_scheme="orange", variant="solid")),
            rx.cond(counts.medium > 0, rx.badge(f"Moy: {counts.medium}", color_scheme="yellow")),
            rx.cond(counts.low > 0, rx.badge(f"Faible: {counts.low}", color_scheme="blue")),
            spacing="1",
        ),
    )


def count_badge(count, label, color_scheme: str = "red") -> rx.Component:
    """A red count with a label, or a green zero."""
    return rx.cond(
        count == 0,
        rx.badge("0", color_scheme="green"),
        rx.badge(label, color_scheme=color_scheme, variant="solid"),
    )


def actionable_badge(count) -> rx.Component:
    """Outstanding issues, linking to the backlog they refer to."""
    return rx.cond(
        count == 0,
        rx.badge("0", color_scheme="green"),
        rx.link(rx.badge(count, color_scheme="amber", variant="solid"), href="/issues"),
    )


def delta_badges(new_issues, resolved_issues) -> rx.Component:
    """What a scan changed: +N new, −M resolved, or a dash.

    The signal a raw finding count cannot give — 400 findings that are all
    already known is not news (see IssueService).
    """
    return rx.hstack(
        rx.cond(new_issues > 0, rx.badge(f"+{new_issues}", color_scheme="red", variant="solid")),
        rx.cond(resolved_issues > 0, rx.badge(f"−{resolved_issues}", color_scheme="green", variant="solid")),
        rx.cond(
            (new_issues == 0) & (resolved_issues == 0),
            rx.text("—", size="2", color="var(--slate-9)"),
        ),
        spacing="1",
    )
