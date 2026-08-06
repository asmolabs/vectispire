import reflex as rx

from zanshin.ui.state import BaseState
from zanshin.ui.auth import requires_admin
from zanshin.ui.layout import main_layout
from zanshin.container import get_container
from zanshin.services.audit_log_service import AuditOperation

ROLE_OPTIONS = ["SUPERUSER", "ADMIN", "USER"]

class UsersState(BaseState):
    """Admin-only user management: create, edit, reset password, delete.

    Guardrails against locking the app out of admin access (can't delete
    your own account, can't delete/demote/deactivate the last active
    SUPERUSER) live in `UserService`, not here — this state just surfaces
    whatever it raises as a toast.
    """

    users: list[dict[str, str]] = []

    # Create dialog
    create_dialog_open: bool = False
    new_username: str = ""
    new_password: str = ""
    new_display_name: str = ""
    new_email: str = ""
    new_role: str = "USER"

    # Edit dialog
    edit_dialog_open: bool = False
    edit_user_id: int = 0
    edit_username: str = ""
    edit_display_name: str = ""
    edit_email: str = ""
    edit_role: str = "USER"
    edit_is_active: bool = True

    # Reset password dialog
    reset_dialog_open: bool = False
    reset_user_id: int = 0
    reset_username: str = ""
    reset_new_password: str = ""

    @requires_admin
    def load_users(self):
        # The role check is `@requires_admin`, not an inline test: it has to
        # hold for a direct websocket call to this handler too, not only for
        # a page load (see zanshin/ui/auth.py).
        self.set_current_page("Utilisateurs")

        container = get_container()
        try:
            db_users = container.user_service.find_all()
            self.users = [
                {
                    "id": str(u.id),
                    "username": u.username,
                    "display_name": u.display_name or u.username,
                    "email": u.email or "—",
                    "role": u.role,
                    "status": "Actif" if u.is_active else "Inactif",
                    "created_at": u.created_at.strftime("%d/%m/%Y %H:%M") if u.created_at else "",
                }
                for u in db_users
            ]
        except Exception as e:
            yield self.trigger_toast(f"Erreur de chargement : {str(e)}", is_error=True)
        finally:
            container.db.close()

    # --- Create ---
    def set_new_username(self, v: str):
        self.new_username = v

    def set_new_password(self, v: str):
        self.new_password = v

    def set_new_display_name(self, v: str):
        self.new_display_name = v

    def set_new_email(self, v: str):
        self.new_email = v

    def set_new_role(self, v: str):
        self.new_role = v

    def open_create_dialog(self):
        self.new_username = ""
        self.new_password = ""
        self.new_display_name = ""
        self.new_email = ""
        self.new_role = "USER"
        self.create_dialog_open = True

    def close_create_dialog(self):
        self.create_dialog_open = False

    @requires_admin
    def create_user(self):
        container = get_container()
        try:
            new_user = container.user_service.create_user(
                username=self.new_username,
                password=self.new_password,
                display_name=self.new_display_name,
                email=self.new_email,
                role=self.new_role,
            )
            container.audit_log_service.record(
                AuditOperation.USER_CREATED,
                resource_id=str(new_user.id),
                description=f"Utilisateur '{new_user.username}' créé (rôle {new_user.role})",
                user_id=self.username,
            )
            self.create_dialog_open = False
            yield self.trigger_toast("Utilisateur créé avec succès")
            yield UsersState.load_users(self)
        except ValueError as e:
            yield self.trigger_toast(str(e), is_error=True)
        except Exception as e:
            yield self.trigger_toast(f"Erreur de création : {str(e)}", is_error=True)
        finally:
            container.db.close()

    # --- Edit ---
    def set_edit_display_name(self, v: str):
        self.edit_display_name = v

    def set_edit_email(self, v: str):
        self.edit_email = v

    def set_edit_role(self, v: str):
        self.edit_role = v

    def set_edit_is_active(self, v: bool):
        self.edit_is_active = v

    @requires_admin
    def open_edit_dialog(self, user_id_str: str):
        container = get_container()
        try:
            user = container.user_service.find_by_id(int(user_id_str))
            if not user:
                yield self.trigger_toast("Utilisateur introuvable", is_error=True)
                return
            self.edit_user_id = user.id
            self.edit_username = user.username
            self.edit_display_name = user.display_name or ""
            self.edit_email = user.email or ""
            self.edit_role = user.role
            self.edit_is_active = user.is_active
            self.edit_dialog_open = True
        finally:
            container.db.close()

    def close_edit_dialog(self):
        self.edit_dialog_open = False

    @requires_admin
    def save_edit(self):
        container = get_container()
        try:
            updated = container.user_service.update_user(
                user_id=self.edit_user_id,
                display_name=self.edit_display_name,
                email=self.edit_email,
                role=self.edit_role,
                is_active=self.edit_is_active,
            )
            container.audit_log_service.record(
                AuditOperation.USER_UPDATED,
                resource_id=str(updated.id),
                description=(
                    f"Utilisateur '{updated.username}' modifié "
                    f"(rôle={updated.role}, actif={updated.is_active})"
                ),
                user_id=self.username,
            )
            self.edit_dialog_open = False
            yield self.trigger_toast("Utilisateur mis à jour")
            yield UsersState.load_users(self)
        except ValueError as e:
            yield self.trigger_toast(str(e), is_error=True)
        except Exception as e:
            yield self.trigger_toast(f"Erreur d'enregistrement : {str(e)}", is_error=True)
        finally:
            container.db.close()

    # --- Reset password ---
    def set_reset_new_password(self, v: str):
        self.reset_new_password = v

    def open_reset_dialog(self, user_id_str: str, username: str):
        self.reset_user_id = int(user_id_str)
        self.reset_username = username
        self.reset_new_password = ""
        self.reset_dialog_open = True

    def close_reset_dialog(self):
        self.reset_dialog_open = False

    @requires_admin
    def confirm_reset_password(self):
        container = get_container()
        try:
            container.user_service.reset_password(self.reset_user_id, self.reset_new_password)
            container.audit_log_service.record(
                AuditOperation.USER_PASSWORD_RESET,
                resource_id=str(self.reset_user_id),
                description=f"Mot de passe réinitialisé pour '{self.reset_username}'",
                user_id=self.username,
            )
            self.reset_dialog_open = False
            yield self.trigger_toast("Mot de passe réinitialisé")
        except ValueError as e:
            yield self.trigger_toast(str(e), is_error=True)
        except Exception as e:
            yield self.trigger_toast(f"Erreur : {str(e)}", is_error=True)
        finally:
            container.db.close()

    # --- Delete ---
    @requires_admin
    def delete_user(self, user_id_str: str):
        container = get_container()
        try:
            user_id = int(user_id_str)
            target = container.user_service.find_by_id(user_id)
            target_username = target.username if target else user_id_str
            container.user_service.delete_user(user_id, self.username)
            container.audit_log_service.record(
                AuditOperation.USER_DELETED,
                resource_id=user_id_str,
                description=f"Utilisateur '{target_username}' supprimé",
                user_id=self.username,
            )
            yield self.trigger_toast("Utilisateur supprimé")
            yield UsersState.load_users(self)
        except ValueError as e:
            yield self.trigger_toast(str(e), is_error=True)
        except Exception as e:
            yield self.trigger_toast(f"Erreur de suppression : {str(e)}", is_error=True)
        finally:
            container.db.close()

def role_select(value: rx.Var, on_change) -> rx.Component:
    return rx.select.root(
        rx.select.trigger(),
        rx.select.content(
            rx.select.group(
                rx.foreach(ROLE_OPTIONS, lambda r: rx.select.item(r, value=r))
            )
        ),
        value=value,
        on_change=on_change,
        width="100%"
    )

def users_page() -> rx.Component:
    """Admin-only user management view (create/edit/reset password/delete)."""
    content = rx.vstack(
        rx.hstack(
            rx.text("Gérez les comptes utilisateurs et leurs rôles", size="2", color="var(--slate-10)"),
            rx.spacer(),
            rx.button("Créer un utilisateur", rx.icon(tag="user-plus"), color_scheme="cyan", on_click=UsersState.open_create_dialog),
            width="100%",
            align="center"
        ),

        rx.box(
            rx.table.root(
                rx.table.header(
                    rx.table.row(
                        rx.table.column_header_cell("Utilisateur"),
                        rx.table.column_header_cell("Nom affiché"),
                        rx.table.column_header_cell("Email"),
                        rx.table.column_header_cell("Rôle"),
                        rx.table.column_header_cell("Statut"),
                        rx.table.column_header_cell("Créé le"),
                        rx.table.column_header_cell("Actions")
                    )
                ),
                rx.table.body(
                    rx.foreach(
                        UsersState.users,
                        lambda u: rx.table.row(
                            rx.table.row_header_cell(u["username"]),
                            rx.table.cell(u["display_name"]),
                            rx.table.cell(u["email"]),
                            rx.table.cell(
                                rx.badge(
                                    u["role"],
                                    color_scheme=rx.cond(
                                        u["role"] == "SUPERUSER",
                                        "red",
                                        rx.cond(u["role"] == "ADMIN", "orange", "gray")
                                    )
                                )
                            ),
                            rx.table.cell(
                                rx.badge(u["status"], color_scheme=rx.cond(u["status"] == "Actif", "green", "gray"))
                            ),
                            rx.table.cell(u["created_at"]),
                            rx.table.cell(
                                rx.hstack(
                                    rx.tooltip(
                                        rx.button(
                                            rx.icon(tag="pencil"),
                                            size="2", color_scheme="teal", variant="soft",
                                            on_click=lambda: UsersState.open_edit_dialog(u["id"])
                                        ),
                                        content="Modifier"
                                    ),
                                    rx.tooltip(
                                        rx.button(
                                            rx.icon(tag="key-round"),
                                            size="2", color_scheme="amber", variant="soft",
                                            on_click=lambda: UsersState.open_reset_dialog(u["id"], u["username"])
                                        ),
                                        content="Réinitialiser le mot de passe"
                                    ),
                                    rx.tooltip(
                                        rx.button(
                                            rx.icon(tag="trash"),
                                            size="2", color_scheme="red", variant="soft",
                                            on_click=lambda: UsersState.delete_user(u["id"])
                                        ),
                                        content="Supprimer"
                                    ),
                                    spacing="2"
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

        # Create dialog
        rx.dialog.root(
            rx.dialog.content(
                rx.dialog.title("Créer un utilisateur"),
                rx.dialog.description("Le mot de passe doit contenir au moins 8 caractères."),
                rx.vstack(
                    rx.vstack(
                        rx.text("Nom d'utilisateur", size="2", weight="bold"),
                        rx.input(value=UsersState.new_username, on_change=UsersState.set_new_username, required=True, class_name="w-full"),
                        width="100%", spacing="1"
                    ),
                    rx.vstack(
                        rx.text("Mot de passe", size="2", weight="bold"),
                        rx.input(type="password", value=UsersState.new_password, on_change=UsersState.set_new_password, required=True, class_name="w-full"),
                        width="100%", spacing="1"
                    ),
                    rx.vstack(
                        rx.text("Nom affiché (optionnel)", size="2", weight="bold"),
                        rx.input(value=UsersState.new_display_name, on_change=UsersState.set_new_display_name, class_name="w-full"),
                        width="100%", spacing="1"
                    ),
                    rx.vstack(
                        rx.text("Email (optionnel)", size="2", weight="bold"),
                        rx.input(value=UsersState.new_email, on_change=UsersState.set_new_email, class_name="w-full"),
                        width="100%", spacing="1"
                    ),
                    rx.vstack(
                        rx.text("Rôle", size="2", weight="bold"),
                        role_select(UsersState.new_role, UsersState.set_new_role),
                        width="100%", spacing="1"
                    ),
                    spacing="3",
                    class_name="mt-4 w-full"
                ),
                rx.hstack(
                    rx.button("Annuler", variant="soft", color_scheme="gray", on_click=UsersState.close_create_dialog),
                    rx.button("Créer", on_click=UsersState.create_user, color_scheme="green"),
                    spacing="3",
                    class_name="mt-6 justify-end"
                ),
                class_name="max-w-md w-full"
            ),
            open=UsersState.create_dialog_open
        ),

        # Edit dialog
        rx.dialog.root(
            rx.dialog.content(
                rx.dialog.title(f"Modifier {UsersState.edit_username}"),
                rx.vstack(
                    rx.vstack(
                        rx.text("Nom affiché", size="2", weight="bold"),
                        rx.input(value=UsersState.edit_display_name, on_change=UsersState.set_edit_display_name, class_name="w-full"),
                        width="100%", spacing="1"
                    ),
                    rx.vstack(
                        rx.text("Email", size="2", weight="bold"),
                        rx.input(value=UsersState.edit_email, on_change=UsersState.set_edit_email, class_name="w-full"),
                        width="100%", spacing="1"
                    ),
                    rx.vstack(
                        rx.text("Rôle", size="2", weight="bold"),
                        role_select(UsersState.edit_role, UsersState.set_edit_role),
                        width="100%", spacing="1"
                    ),
                    rx.hstack(
                        rx.switch(checked=UsersState.edit_is_active, on_change=UsersState.set_edit_is_active),
                        rx.text(rx.cond(UsersState.edit_is_active, "Compte actif", "Compte désactivé"), size="2"),
                        spacing="3", align="center", class_name="mt-2"
                    ),
                    spacing="3",
                    class_name="mt-4 w-full"
                ),
                rx.hstack(
                    rx.button("Annuler", variant="soft", color_scheme="gray", on_click=UsersState.close_edit_dialog),
                    rx.button("Enregistrer", on_click=UsersState.save_edit, color_scheme="cyan"),
                    spacing="3",
                    class_name="mt-6 justify-end"
                ),
                class_name="max-w-md w-full"
            ),
            open=UsersState.edit_dialog_open
        ),

        # Reset password dialog
        rx.dialog.root(
            rx.dialog.content(
                rx.dialog.title(f"Réinitialiser le mot de passe de {UsersState.reset_username}"),
                rx.dialog.description("Au moins 8 caractères. L'utilisateur devra utiliser ce nouveau mot de passe à sa prochaine connexion."),
                rx.vstack(
                    rx.input(
                        type="password",
                        placeholder="Nouveau mot de passe",
                        value=UsersState.reset_new_password,
                        on_change=UsersState.set_reset_new_password,
                        class_name="w-full"
                    ),
                    spacing="2",
                    class_name="mt-4 w-full"
                ),
                rx.hstack(
                    rx.button("Annuler", variant="soft", color_scheme="gray", on_click=UsersState.close_reset_dialog),
                    rx.button("Réinitialiser", on_click=UsersState.confirm_reset_password, color_scheme="amber"),
                    spacing="3",
                    class_name="mt-6 justify-end"
                ),
                class_name="max-w-md w-full"
            ),
            open=UsersState.reset_dialog_open
        ),

        width="100%",
        spacing="4",
        on_mount=UsersState.load_users
    )

    return main_layout(content, "Utilisateurs")
