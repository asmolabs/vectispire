import reflex as rx

def stat_card(
    title: str, value, icon_name: str, color: str = "gray", caption=None, alert=None
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

    **`alert` is what stops the colour from being decoration.** A row of six cards in six
    hues — which is what this application had — spends all of its colour before anything
    has happened, so nothing can stand out afterwards. Pass a condition (`count > 0`) and
    the card is grey until that condition holds, then takes `color`. A red that appears
    only when there is something red to say is worth more than six permanent pastels.
    Leave it `None` and the card is always coloured, which is right for a card whose
    colour is identity rather than alarm.
    """
    # Both branches are plain strings, so this resolves in the browser without either
    # colour having to be known here — which is what lets `alert` be a state Var.
    lit = True if alert is None else alert
    tint = rx.cond(lit, f"var(--{color}-3)", "var(--slate-3)")
    ink = rx.cond(lit, f"var(--{color}-11)", "var(--slate-11)")

    return rx.vstack(
        rx.hstack(
            # A fixed height on the label row, so a title that wraps to two lines does
            # not push its number below its neighbours'. A row of KPI cards is read by
            # scanning the numbers across; one of them sitting lower breaks that in a
            # way that looks like a rendering fault.
            rx.text(title, size="2", color="var(--slate-10)", class_name="leading-tight"),
            rx.spacer(),
            rx.box(
                rx.icon(tag=icon_name, size=20, color=ink),
                # The tint is an inline style, not a `bg-{color}-3` utility class:
                # Tailwind generates only the classes it can *see* in the source, and a
                # class name assembled from a parameter at runtime is invisible to it —
                # so the utility silently produced no background at all.
                background=tint,
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


def _severity_segment(count, token: str, label: str) -> rx.Component:
    """One slice of the severity bar, sized by its share of the row.

    `flex_grow` takes the count itself, so the widths are proportions rather than
    pixels — the bar cannot disagree with the numbers it is drawn from. A zero count
    renders nothing at all rather than a zero-width box, because a `title` on an
    invisible element is a tooltip nobody can reach.
    """
    return rx.cond(
        count > 0,
        rx.box(
            background=f"var(--zs-sev-{token})",
            flex_grow=count.to_string(),
            flex_basis="0",
            custom_attrs={"title": f"{count} {label}"},
        ),
    )


def severity_badges(counts, findings) -> rx.Component:
    """The severity of one row: a total, and a bar showing how it splits.

    **Why this replaced four badges.** The previous version rendered up to four solid
    badges per row (`Crit: 3` `Élevé: 2` `Moy: 2` `Faible: 4`). On a fifty-row table that
    is two hundred coloured rectangles, each a different width, so no two rows line up and
    the column after it wavers. Worse, everything was shouting: solid red next to solid
    orange next to solid yellow, on every row, whether or not the row mattered.

    A fixed-width bar with the total beside it answers the two questions separately —
    *how many* is the number, *how bad* is the shape — and two rows can be compared
    without being read. The exact counts stay reachable on hover.

    The name is unchanged although it no longer draws badges: five call sites use it, and
    renaming it would have been the whole diff for none of the benefit.
    """
    return rx.hstack(
        rx.text(findings, size="2", weight="bold", class_name="min-w-[1.75rem] text-right"),
        rx.cond(
            findings == 0,
            # Nothing found is a statement, not an absence — it gets the green the rest of
            # the application uses for "clear", at full width so the row still has a mark
            # in this column instead of a gap.
            rx.box(background="var(--zs-sev-none)", class_name="w-[6.5rem] h-[6px] rounded-full"),
            rx.hstack(
                _severity_segment(counts.critical, "critical", "critique(s)"),
                _severity_segment(counts.high, "high", "élevée(s)"),
                _severity_segment(counts.medium, "medium", "moyenne(s)"),
                _severity_segment(counts.low, "low", "faible(s)"),
                spacing="0",
                class_name="zs-sevbar",
            ),
        ),
        spacing="2",
        align="center",
    )


def _severity_tile(label: str, value, token: str, icon_name: str) -> rx.Component:
    return rx.vstack(
        rx.hstack(
            rx.icon(tag=icon_name, size=14, color=f"var(--zs-sev-{token})"),
            rx.text(label, size="1", color="var(--slate-11)"),
            spacing="1", align="center", justify="center", width="100%",
        ),
        rx.heading(value, size="5"),
        # The colour is a 3px rule under the tile, not a tinted panel with a border.
        # Four filled panels side by side is four competing surfaces inside a dialog that
        # is already a surface; a rule names the severity without claiming the space.
        border_bottom=f"3px solid var(--zs-sev-{token})",
        class_name="p-3 pb-2 text-center flex-1 rounded-t",
    )


def severity_summary(counts) -> rx.Component:
    """The four-severity header of a scan detail dialog.

    This existed twice, copy-pasted between the repository and container dialogs, with
    eight hard-coded colour pairs that had already drifted apart — one used `yellow` for
    medium where every other screen used `amber`. Sharing it is what makes
    `--zs-sev-*` worth having: one edit now reaches both.
    """
    return rx.hstack(
        _severity_tile("Critique", counts.critical.to(str), "critical", "flame"),
        _severity_tile("Élevé", counts.high.to(str), "high", "triangle-alert"),
        _severity_tile("Moyen", counts.medium.to(str), "medium", "circle-alert"),
        _severity_tile("Faible", counts.low.to(str), "low", "info"),
        spacing="3",
        class_name="w-full mt-4",
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
