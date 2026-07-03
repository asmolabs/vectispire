import reflex as rx
from rxconfig import config

from zanshin.ui.pages.login import login_page
from zanshin.ui.pages.dashboard import dashboard_page
from zanshin.ui.pages.containers import containers_page
from zanshin.ui.pages.ssh_keys import ssh_keys_page
from zanshin.ui.pages.depots import depots_page
from zanshin.ui.pages.api_keys import api_keys_page

app = rx.App()

# Route mappings
app.add_page(login_page, route="/login", title="Zanshin - Connexion")
app.add_page(dashboard_page, route="/dashboard", title="Zanshin - Tableau de Bord")
app.add_page(containers_page, route="/containers", title="Zanshin - Conteneurs")
app.add_page(ssh_keys_page, route="/ssh-keys", title="Zanshin - Clés SSH")
app.add_page(depots_page, route="/depots", title="Zanshin - Dépôts & Scans")
app.add_page(api_keys_page, route="/api-keys", title="Zanshin - Clés API")

# Fallback index route
app.add_page(dashboard_page, route="/")
