import reflex as rx
from typing import Dict, Any, List, Optional
import uuid

from zanshin.container import get_container
from zanshin.models.user import User
from zanshin.services.audit_log_service import AuditOperation

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

    def handle_login(self, form_data: Dict[str, Any]):
        self.loading = True
        yield
        
        username = form_data.get("username", "")
        password = form_data.get("password", "")
        
        container = get_container()
        try:
            user = container.auth_service.authenticate_user(
                username,
                password
            )
            
            if user:
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
