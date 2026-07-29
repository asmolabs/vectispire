import reflex as rx
from typing import List, Dict, Any
import uuid

from zanshin.ui.state import BaseState
from zanshin.ui.layout import main_layout
from zanshin.container import get_container
from zanshin.services.audit_log_service import AuditOperation

class ApiKeysState(BaseState):
    """Handles loading, creating, showing, and deleting API Keys."""
    
    keys: list[dict[str, str]] = []
    
    # Dialog states
    create_dialog_open: bool = False
    display_dialog_open: bool = False
    
    new_name: str = ""
    created_key_raw: str = ""

    def set_new_name(self, val: str):
        self.new_name = val

    def load_keys_data(self):
        self.set_current_page("Clés API")
        container = get_container()
        try:
            db_keys = container.api_key_repository.find_all()
            self.keys = []
            for k in db_keys:
                self.keys.append({
                    "id": str(k.id),
                    "name": k.name,
                    "prefix": f"{k.prefix}..." if k.prefix else "—",
                    "last_used_at": k.last_used_at.strftime("%d/%m/%Y %H:%M") if k.last_used_at else "Jamais",
                    "created_at": k.created_at.strftime("%d/%m/%Y %H:%M") if k.created_at else ""
                })
        except Exception as e:
            yield self.trigger_toast(f"Erreur de chargement : {str(e)}", is_error=True)
        finally:
            container.db.close()

    def open_create_dialog(self):
        self.new_name = ""
        self.create_dialog_open = True

    def close_create_dialog(self):
        self.create_dialog_open = False

    def create_api_key(self):
        if not self.new_name:
            yield self.trigger_toast("Un nom est requis pour la clé", is_error=True)
            return

        container = get_container()
        try:
            saved_key, raw_secret = container.api_key_service.create_key(self.new_name)
            container.audit_log_service.record(
                AuditOperation.API_KEY_CREATED,
                resource_id=str(saved_key.id),
                description=f"Clé API '{saved_key.name}' créée",
                user_id=self.username,
            )

            # Shown once: the raw secret is never stored or displayed again.
            self.created_key_raw = raw_secret
            self.create_dialog_open = False
            self.display_dialog_open = True

            yield self.trigger_toast("Clé API créée avec succès")
            yield ApiKeysState.load_keys_data(self)
        except Exception as e:
            yield self.trigger_toast(f"Erreur de création : {str(e)}", is_error=True)
        finally:
            container.db.close()

    def close_display_dialog(self):
        self.display_dialog_open = False
        self.created_key_raw = ""

    def delete_key(self, key_id_str: str):
        container = get_container()
        try:
            key_uuid = uuid.UUID(key_id_str)
            existing = container.api_key_repository.find_by_id(key_uuid)
            key_name = existing.name if existing else key_id_str
            container.api_key_repository.delete_by_id(key_uuid)
            container.audit_log_service.record(
                AuditOperation.API_KEY_DELETED,
                resource_id=key_id_str,
                description=f"Clé API '{key_name}' supprimée",
                user_id=self.username,
            )
            yield self.trigger_toast("Clé API supprimée")
            yield ApiKeysState.load_keys_data(self)
        except Exception as e:
            yield self.trigger_toast(f"Erreur de suppression : {str(e)}", is_error=True)
        finally:
            container.db.close()

def api_keys_page() -> rx.Component:
    """API key listing and creation page view."""
    content = rx.vstack(
        # Page header controls
        rx.hstack(
            rx.text("Gérez vos clés d'accès personnel pour utiliser l'API Zanshin", size="2", color="var(--slate-10)"),
            rx.spacer(),
            rx.button("Créer une clé API", rx.icon(tag="plus"), color_scheme="indigo", on_click=ApiKeysState.open_create_dialog),
            width="100%",
            align="center"
        ),
        
        # Grid/Table
        rx.box(
            rx.table.root(
                rx.table.header(
                    rx.table.row(
                        rx.table.column_header_cell("Nom"),
                        rx.table.column_header_cell("Clé"),
                        rx.table.column_header_cell("Dernière utilisation"),
                        rx.table.column_header_cell("Créée le"),
                        rx.table.column_header_cell("Actions")
                    )
                ),
                rx.table.body(
                    rx.foreach(
                        ApiKeysState.keys,
                        lambda k: rx.table.row(
                            rx.table.row_header_cell(k["name"]),
                            rx.table.cell(k["prefix"]),
                            rx.table.cell(k["last_used_at"]),
                            rx.table.cell(k["created_at"]),
                            rx.table.cell(
                                rx.tooltip(
                                    rx.button(
                                        rx.icon(tag="trash"),
                                        size="2",
                                        color_scheme="red",
                                        variant="soft",
                                        on_click=lambda: ApiKeysState.delete_key(k["id"])
                                    ),
                                    content="Supprimer"
                                )
                            )
                        )
                    )
                ),
                width="100%"
            ),
            width="100%",
            class_name="p-6 rounded-xl bg-slate-2 border border-slate-4 shadow-sm w-full"
        ),
        
        # Creation modal dialog
        rx.dialog.root(
            rx.dialog.content(
                rx.dialog.title("Créer une clé API"),
                rx.dialog.description("Donnez un nom descriptif à votre clé API."),
                rx.vstack(
                    rx.text("Nom de la clé", size="2", weight="bold"),
                    rx.input(placeholder="Ex: Token CI/CD Jenkins", value=ApiKeysState.new_name, on_change=ApiKeysState.set_new_name, required=True, class_name="w-full"),
                    spacing="2",
                    class_name="mt-4 w-full"
                ),
                rx.hstack(
                    rx.dialog.close(
                        rx.button("Annuler", variant="soft", color_scheme="gray", on_click=ApiKeysState.close_create_dialog)
                    ),
                    rx.button("Créer", on_click=ApiKeysState.create_api_key, color_scheme="green"),
                    spacing="3",
                    class_name="mt-6 justify-end"
                ),
                class_name="max-w-md w-full"
            ),
            open=ApiKeysState.create_dialog_open
        ),
        
        # Display modal dialog
        rx.dialog.root(
            rx.dialog.content(
                rx.dialog.title("Clé API créée"),
                rx.dialog.description("Copiez cette clé maintenant car vous ne pourrez plus la revoir :"),
                rx.vstack(
                    rx.input(value=ApiKeysState.created_key_raw, read_only=True, class_name="w-full text-center font-mono"),
                    spacing="2",
                    class_name="mt-4 w-full"
                ),
                rx.hstack(
                    rx.button("J'ai copié la clé", on_click=ApiKeysState.close_display_dialog, color_scheme="indigo"),
                    class_name="mt-6 justify-end w-full"
                ),
                class_name="max-w-md w-full"
            ),
            open=ApiKeysState.display_dialog_open
        ),
        
        width="100%",
        spacing="4",
        on_mount=ApiKeysState.load_keys_data
    )
    
    return main_layout(content, "Clés API")
