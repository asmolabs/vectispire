"""Refusing, at startup, the deployments that cannot work.

ADR-002 lists what breaks when a second instance appears. Some of it is now fixed —
the claim is transactional (D1), the periodic work has one owner (§2.2), startup
recovery no longer kills another worker's scans (§2.3). Some is not, and cannot be
fixed by this application:

* **SQLite has one writer.** Two instances on one file is not slow, it is corrupt, and
  `FOR UPDATE SKIP LOCKED` does not exist there to make the claim safe (D6).
* **Reflex keeps a client's server-side state on the instance that accepted its
  socket.** Without `state_manager_mode = "redis"`, a client that lands on the other
  instance is intermittently logged out with no error anybody can act on (§2.4).
* **The migration lock is per host.** Two hosts starting together are not coordinated,
  so `ZANSHIN_AUTO_MIGRATE` should be off in a fleet (§2.6).

The point of this module is that an operator learns those *at startup*, from a message
naming the reason, rather than from a corrupt database or from users being logged out
at random.

**How a second instance is detected.** Not by asking the operator — a configuration
flag would be wrong exactly when it matters, because nobody sets it. Each instance
already registers a built-in agent row for its host and refreshes it every tick
(`AgentService.ensure_builtin_agent`), so another live instance is another host's row
with a recent `last_seen_at`. Two limits, both deliberate:

* two instances **on the same host** share one row and are invisible here. That
  deployment has no reason to exist — the second process buys nothing a bigger
  concurrency limit would not — so it is not worth a second mechanism;
* an instance that stopped less than `ONLINE_TTL_SECONDS` ago still looks alive. On
  SQLite this can refuse a restart that happens to reuse a *different* hostname
  within two minutes, which is what a Kubernetes rolling restart does — hence
  `ZANSHIN_ALLOW_MULTI_INSTANCE_SQLITE`, whose only purpose is that case.
"""
import logging
import os
from datetime import timedelta
from typing import List, Optional

from zanshin.clock import utcnow
from zanshin.database import is_sqlite
from zanshin.models.agent import KIND_BUILTIN, ONLINE_TTL_SECONDS, Agent

logger = logging.getLogger(__name__)

# The escape hatch for the false positive described above, and for nothing else: it
# does not make two instances safe on SQLite, it makes this check stop saying so.
ALLOW_MULTI_INSTANCE_SQLITE = (
    os.getenv("ZANSHIN_ALLOW_MULTI_INSTANCE_SQLITE", "false").lower() == "true"
)


class UnsafeDeployment(RuntimeError):
    """The instance must not start: another one is live and this configuration
    cannot support two."""


def check(db, hostname: str, now=None) -> List[str]:
    """Verify this instance may run alongside whatever else is live.

    Returns the warnings worth logging; raises `UnsafeDeployment` for the one case that
    is not a warning. Never raises anything else — a startup check that fails on its own
    bug would be worse than the problem it looks for.
    """
    try:
        others = find_other_live_instances(db, hostname, now)
    except Exception:
        logger.exception("Could not check for other live instances — continuing startup")
        return []

    if not others:
        return []

    names = ", ".join(f"{agent.hostname or agent.name}" for agent in others)
    logger.info("Another Zanshin instance appears to be live: %s", names)

    if is_sqlite() and not ALLOW_MULTI_INSTANCE_SQLITE:
        raise UnsafeDeployment(
            f"Une autre instance Zanshin est active ({names}) alors que la base est "
            "SQLite, qui n'accepte qu'un seul écrivain : deux instances corrompraient "
            "les données, et la réclamation des scans ne peut pas y être rendue sûre "
            "(FOR UPDATE SKIP LOCKED n'existe pas). Utilisez PostgreSQL ou MySQL "
            "(ZANSHIN_DATABASE_URL), ou ne lancez qu'une instance.\n"
            "Si cette instance est en réalité seule — un redémarrage sous un nouveau "
            "nom d'hôte, moins de deux minutes après l'arrêt du précédent —, "
            "ZANSHIN_ALLOW_MULTI_INSTANCE_SQLITE=true lève ce refus."
        )

    warnings = []
    if not _shared_state_configured():
        warnings.append(
            "Plusieurs instances servent l'UI sans état Reflex partagé "
            "(state_manager_mode=\"redis\" et redis_url) : un client qui atterrit sur "
            "l'autre instance sera déconnecté par intermittence, sans erreur "
            "exploitable. Configurez Redis, ou des sessions collantes sur le "
            "répartiteur de charge."
        )
    if _auto_migrate_enabled():
        warnings.append(
            "ZANSHIN_AUTO_MIGRATE est actif alors que plusieurs instances tournent : "
            "le verrou de migration ne coordonne que les processus d'un même hôte. "
            "Appliquez « alembic upgrade head » comme une étape de déploiement à part "
            "et démarrez les instances avec ZANSHIN_AUTO_MIGRATE=false."
        )
    return warnings


def find_other_live_instances(db, hostname: str, now=None) -> List[Agent]:
    """Built-in agents belonging to another host and seen recently."""
    now = now or utcnow()
    cutoff = now - timedelta(seconds=ONLINE_TTL_SECONDS)
    return (
        db.query(Agent)
        .filter(
            Agent.kind == KIND_BUILTIN,
            # A row with no hostname cannot be attributed to another machine, and this
            # check errs towards letting a lone instance start: refusing on a row nobody
            # can identify would be the worst possible failure of a startup guard.
            Agent.hostname.isnot(None),
            Agent.hostname != hostname,
            Agent.last_seen_at.isnot(None),
            Agent.last_seen_at >= cutoff,
        )
        .all()
    )


def _shared_state_configured() -> bool:
    """Whether Reflex is configured to keep client state somewhere both instances can
    reach. Read from the live config rather than the environment: an operator may set
    it in `rxconfig.py`, and what matters is what Reflex ended up with."""
    try:
        from reflex.config import get_config

        config = get_config()
        mode = str(getattr(config, "state_manager_mode", "") or "")
        return "redis" in mode.lower() and bool(getattr(config, "redis_url", None))
    except Exception:
        # Unable to tell. Say nothing rather than warn about a configuration that may
        # well be correct.
        return True


def _auto_migrate_enabled() -> bool:
    try:
        from zanshin.schema import auto_migrate_enabled

        return auto_migrate_enabled()
    except Exception:
        return False


def run(hostname: Optional[str] = None) -> None:
    """Startup entry point: check, log, and stop the process if it must not run.

    Opens its own session, like the other startup tasks, so an unrelated bad setting
    cannot keep this check from running.
    """
    from zanshin.database import SessionLocal
    from zanshin.services.agent_service import _hostname

    db = SessionLocal()
    try:
        for warning in check(db, hostname or _hostname()):
            logger.warning(warning)
    finally:
        db.close()
