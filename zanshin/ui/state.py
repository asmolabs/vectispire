import reflex as rx
from typing import Dict, Any, List, Optional
import uuid

from zanshin.container import get_container
from zanshin.models.user import User
from zanshin.services.audit_log_service import AuditOperation
from zanshin.services.login_throttle import login_throttle

class BaseState(rx.State):
    """Base state for application-wide session, user details, and common properties."""
    
    # Session state
    username: str = ""
    display_name: str = ""
    user_role: str = ""
    logged_in: bool = False
    
    # Navigation tracking
    current_page: str = "Dashboard"
    
    # Error/Notification toasts
    toast_message: str = ""
    toast_is_error: bool = False

    def trigger_toast(self, message: str, is_error: bool = False):
        self.toast_message = message
        self.toast_is_error = is_error
        # Trigger sonner toast via return Event
        if is_error:
            return rx.toast.error(message)
        else:
            return rx.toast.success(message)

    def logout(self):
        self.username = ""
        self.display_name = ""
        self.user_role = ""
        self.logged_in = False
        return rx.redirect("/login")

    def check_auth(self):
        """On-load page check to force login redirection if not authenticated."""
        if not self.logged_in:
            return rx.redirect("/login")

    def set_current_page(self, page_name: str):
        self.current_page = page_name

class LoginState(BaseState):
    """Login page state handles credentials checking."""
    loading: bool = False

    def _client_id(self) -> str:
        """Something to rate-limit on besides the username.

        Reflex gives each connection a token; it is not an IP address, but it is
        what this process can actually observe, and it makes a single client's
        attempts countable. Keying on the username alone would let anyone lock out
        a known account on purpose.
        """
        try:
            return self.router.session.client_token or ""
        except Exception:
            # No router outside a real request (tests, harness): fall back to
            # username-only limiting rather than failing the login.
            return ""

    def handle_login(self, form_data: Dict[str, Any]):
        self.loading = True
        yield

        username = form_data.get("username", "")
        password = form_data.get("password", "")
        client_id = self._client_id()

        # Checked *before* hashing: a locked-out attempt must cost no bcrypt round,
        # otherwise a deliberately-slow hash becomes a way to spend the server's
        # CPU for free (see LoginThrottle).
        allowed, wait_seconds = login_throttle.check(username, client_id)
        if not allowed:
            self.loading = False
            container = get_container()
            try:
                container.audit_log_service.record(
                    AuditOperation.LOGIN_BLOCKED,
                    resource_id=username or "unknown",
                    description=(
                        f"Tentatives de connexion bloquées pour '{username}' "
                        f"(trop d'échecs récents)"
                    ),
                )
            finally:
                container.db.close()
            yield self.trigger_toast(
                f"Trop de tentatives échouées. Réessayez dans {wait_seconds} seconde(s).",
                is_error=True,
            )
            return

        container = get_container()
        try:
            user = container.auth_service.authenticate_user(
                username,
                password
            )

            if user:
                login_throttle.record_success(username, client_id)
                self.logged_in = True
                self.username = user.username
                self.display_name = user.display_name or user.username
                self.user_role = user.role
                self.loading = False

                container.audit_log_service.record(
                    AuditOperation.LOGIN_SUCCESS,
                    resource_id=str(user.id),
                    description=f"Connexion réussie pour '{user.username}'",
                    user_id=user.username,
                )

                # Redirect to dashboard
                yield rx.redirect("/dashboard")
                yield self.trigger_toast("Connexion réussie")
            else:
                self.loading = False
                login_throttle.record_failure(username, client_id)
                container.audit_log_service.record(
                    AuditOperation.LOGIN_FAILURE,
                    resource_id=username or "unknown",
                    description=f"Échec de connexion pour '{username}'",
                )
                yield self.trigger_toast("Identifiants incorrects ou compte inactif", is_error=True)
        except Exception as e:
            self.loading = False
            yield self.trigger_toast(f"Erreur de connexion : {str(e)}", is_error=True)
        finally:
            container.db.close()
