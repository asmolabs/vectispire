import reflex as rx
from zanshin.ui.state import BaseState

def section_label(text: str) -> rx.Component:
    """A heading above a group of navigation links.

    Not a link, and not collapsible: it names a section, the way "Administration" has
    always done. Making these expandable would need per-section state on `BaseState` for
    a sidebar with nine entries."""
    return rx.text(
        text,
        size="1",
        weight="bold",
        color="var(--slate-9)",
        class_name="px-4 mt-4 mb-2 uppercase tracking-wider",
    )


def nav_item(
    label: str, icon_name: str, path: str, current_page: str, class_name: str = ""
) -> rx.Component:
    """Helper to build a navigation link with highlighting."""
    is_active = (current_page == label)

    return rx.link(
        rx.hstack(
            rx.icon(tag=icon_name, size=20, color=rx.cond(is_active, "var(--accent-9)", "var(--slate-10)")),
            rx.text(
                label,
                size="3",
                weight=rx.cond(is_active, "medium", "normal"),
                color=rx.cond(is_active, "var(--accent-9)", "var(--slate-11)")
            ),
            spacing="3",
            align="center",
            class_name=rx.cond(
                is_active,
                "w-full px-4 py-3 rounded-lg transition-all duration-200 cursor-pointer bg-accent-3 border-l-4 border-accent-9",
                "w-full px-4 py-3 rounded-lg transition-all duration-200 cursor-pointer hover:bg-slate-3 hover:translate-x-1"
            )
        ),
        href=path,
        class_name=f"w-full text-none {class_name}".strip(),
    )

def sidebar(current_page: str, user_role: str) -> rx.Component:
    """Navigation sidebar displaying application logo and routing links."""
    return rx.vstack(
        # Header / Brand Section
        rx.hstack(
            rx.icon(tag="shield-check", size=32, color="var(--accent-9)"),
            rx.vstack(
                rx.heading("Zanshin", size="6", weight="bold"),
                rx.text("Cybersecurity Center", size="1", color="var(--slate-10)"),
                spacing="0"
            ),
            spacing="3",
            align="center",
            class_name="px-4 py-6 border-b border-slate-4 w-full"
        ),
        
        # Navigation Items
        rx.vstack(
            nav_item("Tableau de bord", "home", "/dashboard", current_page),

            # Two named sections, on the same pattern as Administration below.
            #
            # Note what the grouping does *not* do: `nav_item` highlights on
            # `current_page == label`, and each page sets that label itself, so visiting
            # /issues highlights "Problèmes" without lighting up "Sécurité". Highlighting
            # a parent would need a label→section map this navigation has no room for,
            # and the cost of not having it is cosmetic.
            #
            # The routes are unchanged: /depots and /containers keep their addresses.
            # Renaming them to sit under a section prefix would break every bookmark for
            # a purely visual gain.
            section_label("Sécurité"),
            nav_item("Sécurité", "shield-check", "/securite", current_page),
            nav_item("Problèmes", "shield-alert", "/issues", current_page),
            nav_item("Dépôts & Scans", "git-branch", "/depots", current_page),
            nav_item("Conteneurs", "box", "/containers", current_page),

            section_label("Qualité"),
            nav_item("Qualité", "sparkles", "/qualite", current_page),

            nav_item("Clés SSH", "key", "/ssh-keys", current_page, class_name="mt-4"),

            # Admin only pages
            rx.cond(
                (user_role == "SUPERUSER") | (user_role == "ADMIN"),
                rx.vstack(
                    section_label("Administration"),
                    nav_item("Clés API", "lock", "/api-keys", current_page),
                    nav_item("Agents", "server", "/agents", current_page),
                    nav_item("Utilisateurs", "users", "/users", current_page),
                    nav_item("Journal d'audit", "scroll-text", "/audit-log", current_page),
                    nav_item("Paramètres", "settings", "/settings", current_page),
                    width="100%",
                    spacing="1"
                )
            ),
            
            width="100%",
            spacing="1",
            class_name="flex-1 p-3 overflow-y-auto w-full"
        ),
        
        # User details + logout section at the bottom
        rx.hstack(
            rx.avatar(fallback=BaseState.username[0:2].upper(), size="2"),
            rx.vstack(
                rx.text(BaseState.display_name, size="2", weight="bold", color="var(--slate-12)"),
                rx.text(BaseState.user_role.lower(), size="1", color="var(--slate-10)"),
                spacing="0"
            ),
            rx.spacer(),
            rx.icon(tag="log-out", size=20, color="var(--slate-10)", class_name="cursor-pointer hover:text-red-9 transition-colors", on_click=BaseState.logout),
            spacing="3",
            align="center",
            class_name="p-4 border-t border-slate-4 w-full bg-slate-2"
        ),
        
        height="100vh",
        class_name="w-64 border-r border-slate-4 flex flex-col bg-slate-1 h-screen sticky top-0"
    )

def main_layout(content: rx.Component, page_title: str) -> rx.Component:
    """Wrapper layout for pages, supplying sidebar and common page structure."""
    return rx.hstack(
        # Sidebar
        sidebar(BaseState.current_page, BaseState.user_role),
        
        # Main content area
        rx.vstack(
            # Top header bar
            rx.hstack(
                rx.heading(page_title, size="6", weight="bold"),
                rx.spacer(),
                rx.color_mode.button(),
                align="center",
                class_name="w-full px-8 py-4 border-b border-slate-4 bg-slate-1/80 backdrop-blur"
            ),
            
            # Scrollable main contents
            rx.box(
                content,
                class_name="w-full p-8 overflow-y-auto flex-1 bg-slate-2/50"
            ),
            
            height="100vh",
            class_name="flex-1 flex flex-col h-screen overflow-hidden"
        ),
        
        width="100%",
        height="100vh",
        on_mount=BaseState.check_auth,  # Verify authentication on loading
        class_name="min-h-screen flex"
    )
