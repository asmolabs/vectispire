from typing import List, Optional

from zanshin.models.user import User
from zanshin.repositories.user_repository import UserRepository
from zanshin.services.auth_service import AuthService

VALID_ROLES = ("SUPERUSER", "ADMIN", "USER")

class UserService:
    """User CRUD for the admin-only /users page.

    Password hashing is delegated to `AuthService` (bcrypt, already used for
    login) rather than duplicated here. Includes guardrails that have
    nothing to do with security scanning but are basic hygiene for any
    admin-facing user management screen: an admin can't delete their own
    account from this page, and the last active SUPERUSER can't be
    deleted, demoted, or deactivated — either would leave the application
    with no one able to manage it.
    """

    def __init__(self, user_repository: UserRepository, auth_service: AuthService):
        self.user_repository = user_repository
        self.auth_service = auth_service

    def find_all(self) -> List[User]:
        return self.user_repository.find_all()

    def find_by_id(self, user_id: int) -> Optional[User]:
        return self.user_repository.find_by_id(user_id)

    def create_user(
        self,
        username: str,
        password: str,
        display_name: str = "",
        email: str = "",
        role: str = "USER",
    ) -> User:
        username = (username or "").strip()
        if not username or not password:
            raise ValueError("Nom d'utilisateur et mot de passe requis.")
        if len(password) < 8:
            raise ValueError("Le mot de passe doit contenir au moins 8 caractères.")
        if role not in VALID_ROLES:
            raise ValueError(f"Rôle invalide : {role}")
        if self.user_repository.find_by_username(username):
            raise ValueError("Ce nom d'utilisateur existe déjà.")
        if email and self.user_repository.find_by_email(email):
            raise ValueError("Cette adresse email est déjà utilisée.")

        user = User(
            username=username,
            password=self.auth_service.hash_password(password),
            display_name=display_name.strip() or username,
            email=email.strip() or None,
            role=role,
            is_active=True,
        )
        return self.user_repository.save(user)

    def update_user(self, user_id: int, display_name: str, email: str, role: str, is_active: bool) -> User:
        user = self.user_repository.find_by_id(user_id)
        if not user:
            raise ValueError("Utilisateur introuvable.")
        if role not in VALID_ROLES:
            raise ValueError(f"Rôle invalide : {role}")
        if email:
            existing = self.user_repository.find_by_email(email)
            if existing and existing.id != user_id:
                raise ValueError("Cette adresse email est déjà utilisée par un autre compte.")

        if user.role == "SUPERUSER" and (role != "SUPERUSER" or not is_active):
            self._ensure_not_last_active_superuser(user_id, "rétrograder ou désactiver")

        user.display_name = display_name.strip() or user.username
        user.email = email.strip() or None
        user.role = role
        user.is_active = is_active
        return self.user_repository.save(user)

    def change_own_password(self, user_id: int, new_password: str) -> User:
        """A user replacing their own password, which clears `must_change_password`.

        Separate from `reset_password` (an admin acting on someone else) because the
        two differ in what they mean: an admin-set password is provisional by nature
        and should require a change, a self-chosen one is not.
        """
        user = self._require_user(user_id)
        self._validate_password(new_password)
        user.password = self.auth_service.hash_password(new_password)
        user.must_change_password = False
        return self.user_repository.save(user)

    def reset_password(self, user_id: int, new_password: str) -> User:
        """An admin setting someone else's password.

        Flags it for replacement: whoever typed it knows it, so it is provisional by
        construction — the same reasoning as the bootstrap password.
        """
        user = self._require_user(user_id)
        self._validate_password(new_password)
        user.password = self.auth_service.hash_password(new_password)
        user.must_change_password = True
        return self.user_repository.save(user)

    def _require_user(self, user_id: int) -> User:
        user = self.user_repository.find_by_id(user_id)
        if not user:
            raise ValueError("Utilisateur introuvable.")
        return user

    @staticmethod
    def _validate_password(password: str) -> None:
        if not password or len(password) < 8:
            raise ValueError("Le mot de passe doit contenir au moins 8 caractères.")

    def delete_user(self, user_id: int, requesting_username: str) -> None:
        user = self.user_repository.find_by_id(user_id)
        if not user:
            return
        if user.username == requesting_username:
            raise ValueError("Vous ne pouvez pas supprimer votre propre compte.")
        if user.role == "SUPERUSER":
            self._ensure_not_last_active_superuser(user_id, "supprimer")
        self.user_repository.delete(user)

    def _ensure_not_last_active_superuser(self, user_id: int, action: str) -> None:
        other_active_superusers = [
            u for u in self.user_repository.find_all()
            if u.id != user_id and u.role == "SUPERUSER" and u.is_active
        ]
        if not other_active_superusers:
            raise ValueError(f"Impossible de {action} le dernier SUPERUSER actif.")
