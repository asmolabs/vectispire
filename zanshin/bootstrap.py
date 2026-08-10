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
from typing import Optional

from zanshin.database import SessionLocal
from zanshin.repositories.agent_repository import AgentRepository
from zanshin.repositories.setting_repository import SettingRepository
from zanshin.repositories.user_repository import UserRepository
from zanshin.services.agent_service import AgentService
from zanshin.services.auth_service import AuthService
from zanshin.services.scan_recovery import reconcile_interrupted_scans
from zanshin.services.settings_service import SettingsService
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
            created = user_service.create_user(
                username=username,
                password=password,
                display_name=username,
                role="SUPERUSER",
            )
            # This password came from the environment: it has been in a compose file,
            # a CI variable, possibly a repository. Provisioning secret, not password.
            created.must_change_password = True
            user_repository.save(created)
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
    """Recover the scans this process left in flight when it last stopped.

    Never raises: the application must start even if this housekeeping can't run.

    The built-in agent is resolved first, and that ordering matters: it is what
    tells recovery which in-flight scans belonged to *this* host. Without it,
    every running scan looks orphaned — which is how starting the web instance
    used to fail the scans a remote agent was busy running (docs/architecture/04).
    """
    db = SessionLocal()
    try:
        reconcile_interrupted_scans(db, local_worker=ensure_builtin_agent())
    except Exception:
        logger.exception("Could not reconcile interrupted scans — continuing startup")
    finally:
        db.close()


def ensure_builtin_agent() -> Optional[str]:
    """Register this process as an agent, and return its worker id.

    Wired by hand for the same reason as the bootstrap superuser above: going
    through `IoCContainer` would build the scanner engine, so an unrelated bad
    `scan_backend` value would stop the instance from registering itself at all.

    Never raises. A failure means this instance runs without a named built-in
    agent: `dispatch` will register it on its first call, so the only thing lost
    is the precision of the recovery pass just above.
    """
    db = SessionLocal()
    try:
        agent = AgentService(
            AgentRepository(db), settings_service=SettingsService(SettingRepository(db))
        ).ensure_builtin_agent()
        logger.info("Built-in scan agent registered: %s", agent.name)
        return agent.worker_id
    except Exception:
        logger.exception("Could not register the built-in scan agent — continuing startup")
        return None
    finally:
        db.close()
