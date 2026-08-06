"""Startup tasks: the first-run administrator account, and scan recovery.

The SQLite database used to be committed to the repository, so a clone came
with accounts already in it. It no longer is (it held bcrypt password hashes
and encrypted SSH private keys), which means a fresh deployment now starts
with an empty `user` table — and Zanshin has no sign-up page, so it would be
unreachable. This creates the first SUPERUSER from the environment instead.

Runs on every startup but does nothing unless the table is empty, so it can't
resurrect an account that was deliberately deleted.
"""
import logging
import os

from zanshin.database import SessionLocal
from zanshin.repositories.user_repository import UserRepository
from zanshin.services.auth_service import AuthService
from zanshin.services.scan_recovery import reconcile_interrupted_scans
from zanshin.services.user_service import UserService

logger = logging.getLogger(__name__)

BOOTSTRAP_USERNAME_ENV_VAR = "ZANSHIN_BOOTSTRAP_USERNAME"
BOOTSTRAP_PASSWORD_ENV_VAR = "ZANSHIN_BOOTSTRAP_PASSWORD"


def ensure_bootstrap_superuser() -> None:
    """Create the initial SUPERUSER if no user exists at all. Never raises:
    a failure here must not prevent the application from starting (the
    operator can still create the account by hand)."""
    db = SessionLocal()
    try:
        # Only the three objects this actually needs, wired by hand rather
        # than through `IoCContainer`: the container also builds the scanner
        # engine, which reads `scan_backend` from the database and raises on an
        # unknown value — an unrelated bad setting would otherwise block the
        # creation of the first administrator.
        user_repository = UserRepository(db)
        if user_repository.find_all():
            return

        username = os.getenv(BOOTSTRAP_USERNAME_ENV_VAR, "").strip()
        password = os.getenv(BOOTSTRAP_PASSWORD_ENV_VAR, "")
        if not username or not password:
            logger.warning(
                "No user account exists and no bootstrap credentials provided. "
                "Set %s and %s (min. 8 characters) and restart to create the first administrator.",
                BOOTSTRAP_USERNAME_ENV_VAR, BOOTSTRAP_PASSWORD_ENV_VAR,
            )
            return

        # Goes through UserService so the password is hashed and validated
        # exactly like one created from the /users page.
        user_service = UserService(user_repository, AuthService(user_repository))
        try:
            user_service.create_user(
                username=username,
                password=password,
                display_name=username,
                role="SUPERUSER",
            )
        except ValueError as e:
            # Rejected credentials (password too short, ...) — the operator's
            # own input, so report the reason plainly rather than as a crash.
            logger.error(
                "Cannot create the initial administrator from %s/%s: %s",
                BOOTSTRAP_USERNAME_ENV_VAR, BOOTSTRAP_PASSWORD_ENV_VAR, e,
            )
            return
        logger.info("Created initial SUPERUSER '%s' from %s", username, BOOTSTRAP_USERNAME_ENV_VAR)
    except Exception:
        logger.exception("Bootstrap of the initial administrator failed — create the account manually")
    finally:
        db.close()


def recover_interrupted_scans() -> None:
    """Fail scans left in flight by a previous process. Never raises: the
    application must start even if this housekeeping can't run."""
    db = SessionLocal()
    try:
        reconcile_interrupted_scans(db)
    except Exception:
        logger.exception("Could not reconcile interrupted scans — continuing startup")
    finally:
        db.close()
