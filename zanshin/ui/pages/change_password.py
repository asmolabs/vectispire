"""Forced replacement of a provisioning password.

`ZANSHIN_BOOTSTRAP_PASSWORD` will have lived in an environment file, a compose file,
a CI variable, maybe a repository. It is a provisioning secret, not a password, and
before this page it stayed valid forever — the account most worth attacking held the
credential most likely to have leaked.

The account is not blocked at login: the user gets in and lands here, because a login
that succeeds and then refuses to go anywhere is indistinguishable from a broken app.
Everything else is guarded by `@requires_login`, so the only thing reachable while
`must_change_password` holds is this form.
"""
import reflex as rx

from zanshin.container import get_container
from zanshin.services.audit_log_service import AuditOperation
from zanshin.ui.auth import requires_login
from zanshin.ui.state import BaseState

MIN_PASSWORD_LENGTH = 8


class ChangePasswordState(BaseState):
    current_password: str = ""
    new_password: str = ""
    confirm_password: str = ""
    saving: bool = False

    def set_current_password(self, value: str):
        self.current_password = value

    def set_new_password(self, value: str):
        self.new_password = value

    def set_confirm_password(self, value: str):
        self.confirm_password = value

    @requires_login
    def submit(self):
        """Verify the current password, then replace it.

        The current password is required even though the user is already
        authenticated: a session left open on an unlocked laptop must not be enough
        to take the account over.
        """
        if self.new_password != self.confirm_password:
            yield self.trigger_toast("Les deux mots de passe ne correspondent pas.", is_error=True)
            return
        if len(self.new_password) < MIN_PASSWORD_LENGTH:
            yield self.trigger_toast(
                f"Le mot de passe doit contenir au moins {MIN_PASSWORD_LENGTH} caractères.",
                is_error=True,
            )
            return
        if self.new_password == self.current_password:
            yield self.trigger_toast(
                "Le nouveau mot de passe doit être différent de l'actuel.", is_error=True
            )
            return

        self.saving = True
        container = get_container()
        try:
            user = container.auth_service.authenticate_user(self.username, self.current_password)
            if not user:
                self.saving = False
                yield self.trigger_toast("Mot de passe actuel incorrect.", is_error=True)
                return

            container.user_service.change_own_password(user.id, self.new_password)
            container.audit_log_service.record(
                AuditOperation.PASSWORD_CHANGED,
                resource_id=str(user.id),
                description=f"Mot de passe changé par '{user.username}'",
                user_id=user.username,
            )
            self.must_change_password = False
            self.current_password = ""
            self.new_password = ""
            self.confirm_password = ""
            self.saving = False
            yield rx.redirect("/dashboard")
            yield self.trigger_toast("Mot de passe mis à jour")
        except ValueError as e:
            self.saving = False
            yield self.trigger_toast(str(e), is_error=True)
        except Exception as e:
            self.saving = False
            yield self.trigger_toast(f"Erreur : {str(e)}", is_error=True)
        finally:
            container.db.close()


def change_password_page() -> rx.Component:
    """Deliberately outside `main_layout`: no sidebar, nothing else to click. The
    only way forward from a provisioning password is through this form."""
    return rx.center(
        rx.vstack(
            rx.hstack(
                rx.icon(tag="shield-alert", size=28, color="var(--amber-9)"),
                rx.heading("Changer le mot de passe", size="6", weight="bold"),
                spacing="3",
                align="center",
            ),
            rx.cond(
                ChangePasswordState.must_change_password,
                rx.callout(
                    "Ce compte utilise le mot de passe de provisionnement. Il a pu passer "
                    "par un fichier d'environnement ou un dépôt : remplacez-le avant "
                    "d'utiliser l'application.",
                    icon="triangle-alert",
                    color_scheme="amber",
                    size="1",
                ),
            ),
            rx.input(
                placeholder="Mot de passe actuel",
                type="password",
                value=ChangePasswordState.current_password,
                on_change=ChangePasswordState.set_current_password,
                width="100%",
            ),
            rx.input(
                placeholder=f"Nouveau mot de passe ({MIN_PASSWORD_LENGTH} caractères minimum)",
                type="password",
                value=ChangePasswordState.new_password,
                on_change=ChangePasswordState.set_new_password,
                width="100%",
            ),
            rx.input(
                placeholder="Confirmer le nouveau mot de passe",
                type="password",
                value=ChangePasswordState.confirm_password,
                on_change=ChangePasswordState.set_confirm_password,
                width="100%",
            ),
            rx.button(
                "Enregistrer",
                on_click=ChangePasswordState.submit,
                loading=ChangePasswordState.saving,
                color_scheme="cyan",
                width="100%",
            ),
            spacing="4",
            width="100%",
            class_name="p-8 rounded-xl bg-slate-2 border border-slate-4 shadow-lg max-w-md",
        ),
        class_name="min-h-screen w-full",
        on_mount=ChangePasswordState.check_auth,
    )
