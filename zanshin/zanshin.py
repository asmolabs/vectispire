import reflex as rx
from rxconfig import config

from zanshin.ui.pages.login import login_page
from zanshin.ui.pages.dashboard import dashboard_page
from zanshin.ui.pages.containers import containers_page
from zanshin.ui.pages.ssh_keys import ssh_keys_page
from zanshin.ui.pages.depots import depots_page
from zanshin.ui.pages.api_keys import api_keys_page
from zanshin.ui.pages.settings import settings_page
from zanshin.ui.pages.users import users_page
from zanshin.ui.pages.audit_log import audit_log_page

# There is no migration tool wired up yet (the SQLite file predates the
# current codebase and was previously managed by an earlier implementation's
# own migration tooling).
# `create_all` is safe to run on every startup: it only creates tables that
# don't exist yet (e.g. `finding`, `api_key`) and never touches or alters
# existing ones. Adding a column to an existing table still requires a
# manual migration — see docs/architecture/ADR-001-scanner-backends.md.
from zanshin.database import Base, engine as _db_engine
import zanshin.models  # noqa: F401 (ensures every model is registered on Base.metadata)
Base.metadata.create_all(bind=_db_engine)

app = rx.App()

# Route mappings
app.add_page(login_page, route="/login", title="Zanshin - Connexion")
app.add_page(dashboard_page, route="/dashboard", title="Zanshin - Tableau de Bord")
app.add_page(containers_page, route="/containers", title="Zanshin - Conteneurs")
app.add_page(ssh_keys_page, route="/ssh-keys", title="Zanshin - Clés SSH")
app.add_page(depots_page, route="/depots", title="Zanshin - Dépôts & Scans")
app.add_page(api_keys_page, route="/api-keys", title="Zanshin - Clés API")
app.add_page(settings_page, route="/settings", title="Zanshin - Paramètres")
app.add_page(users_page, route="/users", title="Zanshin - Utilisateurs")
app.add_page(audit_log_page, route="/audit-log", title="Zanshin - Journal d'audit")

# Fallback index route
app.add_page(dashboard_page, route="/")
