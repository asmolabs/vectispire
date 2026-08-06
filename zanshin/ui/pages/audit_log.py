import reflex as rx

from zanshin.ui.state import BaseState
from zanshin.ui.auth import requires_admin
from zanshin.ui.layout import main_layout
from zanshin.container import get_container

class AuditLogState(BaseState):
    """Read-only view over `audit_logs` (see AuditLogService) — the most
    recent admin/security-relevant actions: logins, user management, API
    key lifecycle, settings changes."""

    entries: list[dict[str, str]] = []

    @requires_admin
    def load_entries(self):
        # The role check is `@requires_admin`, not an inline test: it has to
        # hold for a direct websocket call to this handler too, not only for
        # a page load (see zanshin/ui/auth.py).
        self.set_current_page("Journal d'audit")

        container = get_container()
        try:
            recent = container.audit_log_service.find_recent(200)
            self.entries = [
                {
                    "timestamp": e.timestamp.strftime("%d/%m/%Y %H:%M:%S") if e.timestamp else "",
                    "operation_type": e.operation_type,
                    "user_id": e.user_id or "Système",
                    "resource_id": e.resource_id,
                    "description": e.description,
                }
                for e in recent
            ]
        except Exception as ex:
            yield self.trigger_toast(f"Erreur de chargement : {str(ex)}", is_error=True)
        finally:
            container.db.close()

def audit_log_page() -> rx.Component:
    """Admin-only audit trail view."""
    content = rx.vstack(
        rx.hstack(
            rx.text(
                "Actions d'administration et de sécurité récentes (connexions, utilisateurs, clés API, réglages).",
                size="2", color="var(--slate-10)"
            ),
            rx.spacer(),
            rx.button("Rafraîchir", rx.icon(tag="refresh-cw"), variant="soft", color_scheme="gray", on_click=AuditLogState.load_entries),
            width="100%",
            align="center"
        ),

        rx.box(
            rx.table.root(
                rx.table.header(
                    rx.table.row(
                        rx.table.column_header_cell("Date"),
                        rx.table.column_header_cell("Type"),
                        rx.table.column_header_cell("Utilisateur"),
                        rx.table.column_header_cell("Ressource"),
                        rx.table.column_header_cell("Description")
                    )
                ),
                rx.table.body(
                    rx.foreach(
                        AuditLogState.entries,
                        lambda e: rx.table.row(
                            rx.table.cell(e["timestamp"]),
                            rx.table.cell(rx.badge(e["operation_type"], variant="soft")),
                            rx.table.cell(e["user_id"]),
                            rx.table.cell(e["resource_id"]),
                            rx.table.cell(e["description"])
                        )
                    )
                ),
                width="100%"
            ),
            width="100%",
            class_name="p-6 rounded-xl bg-slate-2 border border-slate-4 shadow-sm w-full"
        ),

        width="100%",
        spacing="4",
        on_mount=AuditLogState.load_entries
    )

    return main_layout(content, "Journal d'audit")
