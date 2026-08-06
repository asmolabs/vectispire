import os
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import reflex as rx

from zanshin.clock import utcnow
from zanshin.container import get_container
from zanshin.models.user import User
from zanshin.services.audit_log_service import AuditOperation
from zanshin.services.login_throttle import login_throttle

# How long a session stays valid without re-authenticating.
#
# Reflex keeps state server-side, keyed by a client token in localStorage. That token
# never expires on its own and `logout` cannot invalidate it — so without a check
# like this one, a captured token is valid forever. This is not a substitute for
# revocable server-side sessions (which Reflex does not offer here); it bounds the
# window, which is the part that can be fixed from inside the application.
SESSION_TTL = timedelta(hours=int(os.getenv("ZANSHIN_SESSION_TTL_HOURS", "12")))


class BaseState(rx.State):
    """Base state for application-wide session, user details, and common properties."""

    # Session state
    username: str = ""
    display_name: str = ""
    user_role: str = ""
    logged_in: bool = False
    # When the current session authenticated. ISO string rather than a datetime:
    # Reflex serializes state vars, and a plain string travels without surprises.
    authenticated_at: str = ""
    must_change_password: bool = False
    
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

    def _clear_session(self) -> None:
        """Plain method, not an event handler, so it can be called directly.

        `check_auth` used to return `BaseState.logout(self)`: on a state class that
        is attribute access on an `EventHandler`, so it built an event spec instead
        of clearing anything. The session did eventually get cleared — on the next
        round trip, after the page had already mounted and its other `on_mount`
        handlers had loaded the data the expired session was not supposed to see.
        """
        self.username = ""
        self.display_name = ""
        self.user_role = ""
        self.logged_in = False
        self.authenticated_at = ""
        self.must_change_password = False

    def logout(self):
        self._clear_session()
        return rx.redirect("/login")

    def session_expired(self) -> bool:
        """Whether this session has outlived `SESSION_TTL`.

        A missing or unparseable timestamp counts as expired: a session that cannot
        prove when it started is one this check cannot vouch for, and failing open
        would make the whole thing decorative.
        """
        if not self.logged_in:
            return False
        if not self.authenticated_at:
            return True
        try:
            started = datetime.fromisoformat(self.authenticated_at)
        except ValueError:
            return True
        return utcnow() - started >= SESSION_TTL

    def check_auth(self):
        """On-load page check: not authenticated, or authenticated too long ago."""
        if not self.logged_in:
            return rx.redirect("/login")
        if self.session_expired():
            self._clear_session()
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
                self.authenticated_at = utcnow().isoformat()
                self.must_change_password = bool(user.must_change_password)
                self.loading = False

                container.audit_log_service.record(
                    AuditOperation.LOGIN_SUCCESS,
                    resource_id=str(user.id),
                    description=f"Connexion réussie pour '{user.username}'",
                    user_id=user.username,
                )

                if user.must_change_password:
                    # The bootstrap password lived in an environment file, a compose
                    # file, maybe a repository: it is a provisioning secret, not a
                    # password. Nothing else is reachable until it is replaced.
                    yield rx.redirect("/change-password")
                    yield self.trigger_toast(
                        "Mot de passe provisoire : choisissez-en un nouveau.", is_error=True
                    )
                else:
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
