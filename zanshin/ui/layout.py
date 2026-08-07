"""The application shell, modelled on the Sakai admin template (sakai.primeng.org).

Three things about that template carry most of its look, and all three are structural
rather than decorative:

- **A full-width top bar above everything**, 56px tall, holding the brand on the left and
  the account controls on the right. The sidebar starts *below* it rather than beside it.
- **The sidebar is a card, not a wall.** It floats with the same 28px gutter as everything
  else, so the page background shows all the way around it. A sidebar flush to the window
  edge reads as an application frame; this reads as a document.
- **No borders, no shadows.** Surfaces are told apart by background alone. It is the
  single easiest thing to get wrong when copying the style, because every component
  library's default is to draw a line.

Geometry lives in `assets/theme.css` against Radix's `--slate-*` scale, so the light/dark
toggle in the top bar switches between two versions of the same design.
"""
import reflex as rx

from zanshin.ui.state import BaseState


def section_label(text: str) -> rx.Component:
    """A heading above a group of navigation links.

    Not a link and not collapsible: it names a section, the way "Administration" always
    has. Making these expandable would need per-section state on `BaseState` for a
    sidebar of nine entries."""
    return rx.text(text, class_name="zs-nav-section")


def nav_item(label: str, icon_name: str, path: str, current_page: str) -> rx.Component:
    """One navigation link.

    The active state is coloured text and a heavier weight — no filled pill, no left
    border. That is the reference's choice, and it is why the sidebar stays quiet: only
    one line in it is ever coloured.
    """
    is_active = current_page == label

    return rx.link(
        rx.icon(
            tag=icon_name,
            size=18,
            color=rx.cond(is_active, "var(--accent-11)", "var(--slate-10)"),
        ),
        rx.text(label, size="2"),
        href=path,
        class_name="zs-nav-item text-none",
        # A data attribute rather than two class strings: the styling lives in one CSS
        # rule that can express hover and active together.
        custom_attrs={"data-active": rx.cond(is_active, "true", "false")},
    )


def topbar() -> rx.Component:
    return rx.hstack(
        rx.hstack(
            rx.icon(tag="shield-check", size=26, color="var(--accent-9)"),
            rx.heading("Zanshin", size="5", weight="bold"),
            spacing="2",
            align="center",
        ),
        rx.spacer(),
        rx.hstack(
            rx.color_mode.button(),
            rx.menu.root(
                rx.menu.trigger(
                    rx.hstack(
                        rx.avatar(fallback=BaseState.username[0:2].upper(), size="2"),
                        rx.vstack(
                            rx.text(BaseState.display_name, size="2", weight="bold"),
                            rx.text(
                                BaseState.user_role.lower(),
                                size="1",
                                color="var(--slate-10)",
                            ),
                            spacing="0",
                            align_items="start",
                            class_name="hidden sm:flex",
                        ),
                        spacing="2",
                        align="center",
                        class_name="cursor-pointer",
                    )
                ),
                rx.menu.content(
                    rx.menu.item(
                        "Se déconnecter",
                        rx.icon(tag="log-out", size=14),
                        on_click=BaseState.logout,
                        color="var(--red-11)",
                    ),
                ),
            ),
            spacing="4",
            align="center",
        ),
        class_name="zs-topbar w-full",
        align="center",
    )


def sidebar(current_page: str, user_role: str) -> rx.Component:
    return rx.box(
        nav_item("Tableau de bord", "home", "/dashboard", current_page),

        # Two named sections, plus Administration below.
        #
        # Note what the grouping does *not* do: the active state is matched on
        # `current_page == label`, and each page sets that label itself, so visiting
        # /issues highlights "Problèmes" without lighting up "Sécurité". Highlighting a
        # parent would need a label→section map this navigation has no room for, and its
        # absence costs nothing but a highlight.
        #
        # The routes are unchanged: /depots and /containers keep their addresses.
        # Renaming them to sit under a section prefix would break every bookmark for a
        # purely visual gain.
        section_label("Sécurité"),
        nav_item("Sécurité", "shield-check", "/securite", current_page),
        nav_item("Problèmes", "shield-alert", "/issues", current_page),
        nav_item("Dépôts & Scans", "git-branch", "/depots", current_page),
        nav_item("Conteneurs", "box", "/containers", current_page),

        section_label("Qualité"),
        nav_item("Qualité", "sparkles", "/qualite", current_page),

        section_label("Exploitation"),
        nav_item("Clés SSH", "key", "/ssh-keys", current_page),

        rx.cond(
            (user_role == "SUPERUSER") | (user_role == "ADMIN"),
            rx.box(
                section_label("Administration"),
                nav_item("Clés API", "lock", "/api-keys", current_page),
                nav_item("Agents", "server", "/agents", current_page),
                nav_item("Utilisateurs", "users", "/users", current_page),
                nav_item("Journal d'audit", "scroll-text", "/audit-log", current_page),
                nav_item("Paramètres", "settings", "/settings", current_page),
                class_name="w-full",
            ),
        ),

        class_name="zs-sidebar",
    )


def main_layout(content: rx.Component, page_title: str) -> rx.Component:
    """Wrapper layout for pages: top bar, floating sidebar, content column."""
    return rx.box(
        topbar(),
        rx.hstack(
            sidebar(BaseState.current_page, BaseState.user_role),
            rx.box(
                rx.heading(page_title, size="6", weight="bold", class_name="mb-5"),
                content,
                class_name="zs-main flex-1",
            ),
            spacing="0",
            align="start",
            width="100%",
        ),
        width="100%",
        min_height="100vh",
        on_mount=BaseState.check_auth,  # Verify authentication on loading
    )
