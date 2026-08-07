import reflex as rx

def stat_card(
    title: str, value, icon_name: str, color: str = "accent", caption=None
) -> rx.Component:
    """Shared KPI card — the signature element of the Sakai template.

    Its shape is specific and worth keeping exactly: the label sits small and grey on
    the *first* line with the icon opposite it, and the number comes underneath, large.
    The usual arrangement — number and label stacked on the left, icon floated right —
    reads as an icon with a caption; this one reads as a labelled measurement, which is
    what a KPI is.

    The icon lives in a tinted square rather than on the card background. That tint is
    what lets a row of five cards carry five different meanings without five different
    card colours, and it is why `color` is a Radix accent name rather than a hex value:
    it has to hold up in both appearances.

    `caption` is the reference's third line — the small qualifier under the number
    ("24 new since last visit"). Optional, because a number with nothing useful to say
    about itself is better left alone than padded.
    """
    return rx.vstack(
        rx.hstack(
            # A fixed height on the label row, so a title that wraps to two lines does
            # not push its number below its neighbours'. A row of KPI cards is read by
            # scanning the numbers across; one of them sitting lower breaks that in a
            # way that looks like a rendering fault.
            rx.text(title, size="2", color="var(--slate-10)", class_name="leading-tight"),
            rx.spacer(),
            rx.box(
                rx.icon(tag=icon_name, size=20, color=f"var(--{color}-11)"),
                # The tint is an inline style, not a `bg-{color}-3` utility class:
                # Tailwind generates only the classes it can *see* in the source, and a
                # class name assembled from a parameter at runtime is invisible to it —
                # so the utility silently produced no background at all.
                background=f"var(--{color}-3)",
                class_name="zs-stat-icon",
            ),
            width="100%",
            align="start",
            class_name="min-h-[2.5rem]",
        ),
        rx.heading(value, size="7", weight="bold"),
        rx.cond(
            caption is not None,
            rx.text(caption, size="1", color="var(--slate-10)"),
        ),
        spacing="2",
        align_items="start",
        class_name="zs-card flex-1 min-w-[180px]",
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
        class_name="zs-card flex-1"
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
        class_name="w-full py-16 zs-empty"
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
