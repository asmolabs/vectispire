import reflex as rx
from typing import List, Dict, Any
import uuid

from zanshin.ui.state import BaseState
from zanshin.ui.auth import requires_admin
from zanshin.models.api_key import ALL_SCOPES
from zanshin.ui.view_models import ApiKeyRow, format_datetime
from zanshin.ui.layout import main_layout
from zanshin.container import get_container
from zanshin.services.audit_log_service import AuditOperation

class ApiKeysState(BaseState):
    """Handles loading, creating, showing, and deleting API Keys.

    Admin-only, and that is a security boundary rather than tidiness: a key grants
    the whole HTTP API — trigger scans, read every issue of every target, export
    VEX — with no scope of its own. While this page was merely `@requires_login`,
    any USER could mint themselves one and step around the role they were given.
    """
    
    keys: list[ApiKeyRow] = []
    
    # Dialog states
    create_dialog_open: bool = False
    display_dialog_open: bool = False
    
    new_name: str = ""
    created_key_raw: str = ""
    # Narrowing offered, not imposed: defaults match what a key already granted, so
    # a create form cannot silently break the pipeline someone is issuing it for.
    new_scopes: list[str] = list(ALL_SCOPES)
    new_target: str = ""          # "", "repository:3", "container:1"
    new_expires_in_days: str = ""  # empty = no expiry
    targets: list[dict[str, str]] = []

    def set_new_name(self, val: str):
        self.new_name = val

    def toggle_scope(self, scope: str, enabled: bool):
        if enabled and scope not in self.new_scopes:
            self.new_scopes = [s for s in ALL_SCOPES if s in self.new_scopes + [scope]]
        elif not enabled:
            self.new_scopes = [s for s in self.new_scopes if s != scope]

    def set_new_target(self, value: str):
        self.new_target = value

    def set_new_expires_in_days(self, value: str):
        self.new_expires_in_days = value

    @requires_admin
    def load_keys_data(self):
        self.set_current_page("Clés API")
        container = get_container()
        try:
            db_keys = container.api_key_repository.find_all()
            self.keys = [
                ApiKeyRow(
                    id=str(k.id),
                    name=k.name,
                    prefix=f"{k.prefix}..." if k.prefix else "—",
                    last_used_at=format_datetime(k.last_used_at) or "Jamais",
                    created_at=format_datetime(k.created_at),
                    scopes=", ".join(k.scope_list),
                    target=(
                        f"{k.target_kind} #{k.target_id}" if k.target_kind else "Toutes"
                    ),
                    expires_at=format_datetime(k.expires_at) or "Jamais",
                    is_expired=k.is_expired,
                )
                for k in db_keys
            ]

            # Offered as a restriction target, so nobody has to look up an id.
            self.targets = [{"label": "Toutes les cibles", "value": ""}] + [
                {"label": f"Dépôt : {r.name or r.url}", "value": f"repository:{r.id}"}
                for r in container.repository_repository.find_all()
            ] + [
                {"label": f"Image : {c.image_string}", "value": f"container:{c.id}"}
                for c in container.container_repository.find_all()
            ]
        except Exception as e:
            yield self.trigger_toast(f"Erreur de chargement : {str(e)}", is_error=True)
        finally:
            container.db.close()

    def open_create_dialog(self):
        self.new_name = ""
        self.create_dialog_open = True

    def close_create_dialog(self):
        self.create_dialog_open = False

    @requires_admin
    def create_api_key(self):
        if not self.new_name:
            yield self.trigger_toast("Un nom est requis pour la clé", is_error=True)
            return

        container = get_container()
        try:
            target_kind, target_id = (None, None)
            if self.new_target:
                kind, _, raw_id = self.new_target.partition(":")
                target_kind, target_id = kind, int(raw_id)

            saved_key, raw_secret = container.api_key_service.create_key(
                self.new_name,
                scopes=self.new_scopes,
                target_kind=target_kind,
                target_id=target_id,
                expires_in_days=int(self.new_expires_in_days) if self.new_expires_in_days.strip().isdigit() else None,
            )
            container.audit_log_service.record(
                AuditOperation.API_KEY_CREATED,
                resource_id=str(saved_key.id),
                description=(
                    f"Clé API '{saved_key.name}' créée "
                    f"(portées : {saved_key.scopes}, cible : {saved_key.target_kind or 'toutes'})"
                ),
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

    @requires_admin
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
            rx.button("Créer une clé API", rx.icon(tag="plus"), color_scheme="cyan", on_click=ApiKeysState.open_create_dialog),
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
                            rx.table.row_header_cell(k.name),
                            rx.table.cell(k.prefix),
                            rx.table.cell(k.last_used_at),
                            rx.table.cell(k.created_at),
                            rx.table.cell(
                                rx.tooltip(
                                    rx.button(
                                        rx.icon(tag="trash"),
                                        size="2",
                                        color_scheme="red",
                                        variant="soft",
                                        on_click=lambda: ApiKeysState.delete_key(k.id)
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

                    rx.text("Portées", size="2", weight="bold", class_name="mt-3"),
                    rx.text(
                        "Une clé donne accès à toute l'API par défaut. Ne cochez que ce dont "
                        "l'appelant a besoin : « read » pour lire un verdict, « scan » pour en "
                        "déclencher un, « export » pour les documents VEX/CSV/SBOM.",
                        size="1", color="var(--slate-10)",
                    ),
                    *[
                        rx.hstack(
                            rx.checkbox(
                                default_checked=True,
                                on_change=lambda enabled, s=scope: ApiKeysState.toggle_scope(s, enabled),
                            ),
                            rx.text(scope, size="2"),
                            spacing="2", align="center",
                        )
                        for scope in ALL_SCOPES
                    ],

                    rx.text("Restreindre à une cible", size="2", weight="bold", class_name="mt-3"),
                    rx.text(
                        "Sans restriction, une clé émise pour un projet lit aussi les problèmes, "
                        "VEX et exports de tous les autres.",
                        size="1", color="var(--slate-10)",
                    ),
                    rx.select.root(
                        rx.select.trigger(placeholder="Toutes les cibles"),
                        rx.select.content(
                            rx.select.group(
                                rx.foreach(
                                    ApiKeysState.targets,
                                    lambda opt: rx.select.item(opt["label"], value=opt["value"]),
                                )
                            )
                        ),
                        value=ApiKeysState.new_target,
                        on_change=ApiKeysState.set_new_target,
                        width="100%",
                    ),

                    rx.text("Expiration (jours)", size="2", weight="bold", class_name="mt-3"),
                    rx.input(
                        placeholder="vide = n'expire jamais",
                        value=ApiKeysState.new_expires_in_days,
                        on_change=ApiKeysState.set_new_expires_in_days,
                        class_name="w-full",
                    ),
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
                    rx.button("J'ai copié la clé", on_click=ApiKeysState.close_display_dialog, color_scheme="cyan"),
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
