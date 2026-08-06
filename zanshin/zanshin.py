import reflex as rx
from rxconfig import config

from zanshin.ui.pages.login import login_page
from zanshin.ui.pages.change_password import change_password_page
from zanshin.ui.pages.dashboard import dashboard_page
from zanshin.ui.pages.containers import containers_page
from zanshin.ui.pages.ssh_keys import ssh_keys_page
from zanshin.ui.pages.depots import depots_page
from zanshin.ui.pages.issues import issues_page
from zanshin.ui.pages.api_keys import api_keys_page
from zanshin.ui.pages.settings import settings_page
from zanshin.ui.pages.users import users_page
from zanshin.ui.pages.audit_log import audit_log_page

# Schema is managed by Alembic (see zanshin/schema.py). This replaces the
# previous `Base.metadata.create_all`, which could only add whole tables and so
# blocked every column change — the limitation recorded in
# docs/architecture/ADR-001-scanner-backends.md.
import zanshin.models  # noqa: F401 (ensures every model is registered on Base.metadata)
from zanshin.schema import upgrade_to_head
upgrade_to_head()

# The database file is no longer committed to the repository (it contained
# password hashes and encrypted SSH keys), so a fresh deployment starts with no
# accounts and no way to sign up — see zanshin/bootstrap.py.
from zanshin.bootstrap import ensure_bootstrap_superuser
ensure_bootstrap_superuser()

# Any scan still marked in-flight belongs to a process that no longer exists:
# its worker thread died with the previous run. Left alone, those rows are what
# "the latest scan of this target" resolves to, which corrupts the issue
# lifecycle as well as the display (see zanshin/services/scan_recovery.py).
from zanshin.bootstrap import recover_interrupted_scans
recover_interrupted_scans()

# The programmatic API (see zanshin/api/) is mounted onto the same ASGI app, so
# it is served from the same process and port as the UI. This is what finally
# gives the API keys a consumer: they could be issued from the UI and presented
# to nothing.
from zanshin.api import api_app

app = rx.App(api_transformer=api_app)

# Periodic rescanning (see zanshin/services/scheduler.py), started as a Reflex
# lifespan task rather than at import time.
#
# Import-time was wrong in a way that bit immediately: `reflex compile --dry`
# imports this module, so *compiling the app dispatched a real container scan* —
# scan 13 in the development database was created that way. A lifespan task only
# runs when the app actually serves requests.
from zanshin.services import scheduler


@app.register_lifespan_task
async def _start_scan_scheduler():
    scheduler.start()

# Route mappings
app.add_page(login_page, route="/login", title="Zanshin - Connexion")
app.add_page(change_password_page, route="/change-password", title="Zanshin - Mot de passe")
app.add_page(dashboard_page, route="/dashboard", title="Zanshin - Tableau de Bord")
app.add_page(containers_page, route="/containers", title="Zanshin - Conteneurs")
app.add_page(ssh_keys_page, route="/ssh-keys", title="Zanshin - Clés SSH")
app.add_page(depots_page, route="/depots", title="Zanshin - Dépôts & Scans")
app.add_page(issues_page, route="/issues", title="Zanshin - Problèmes")
app.add_page(api_keys_page, route="/api-keys", title="Zanshin - Clés API")
app.add_page(settings_page, route="/settings", title="Zanshin - Paramètres")
app.add_page(users_page, route="/users", title="Zanshin - Utilisateurs")
app.add_page(audit_log_page, route="/audit-log", title="Zanshin - Journal d'audit")

# Fallback index route
app.add_page(dashboard_page, route="/")
