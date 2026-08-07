"""Agents: who runs the scans, and what is waiting to be run.

This screen exists because execution used to be invisible. Scans were claimed by
"the process", ran on "the pool", and an operator watching a queue that had stopped
moving had no way to tell a busy host from a disabled one from an agent that died
mid-scan.

Two tables answer that. The first lists the workers — including the built-in one,
this very process, which is the row that makes a single-machine install work with no
configuration and the switch that moves execution elsewhere. The second lists the
queue, with who holds each job and until when.

Admin-only, and that is a security boundary: registering an agent issues a
credential that may submit scan results, and results are what a gate is evaluated
against.
"""
import reflex as rx

from zanshin.container import get_container
from zanshin.models.agent import (
    CREDENTIALS_DELEGATED,
    CREDENTIALS_LOCAL,
    STATUS_DISABLED,
    STATUS_ONLINE,
)
from zanshin.services import leader_election
from zanshin.services.audit_log_service import AuditOperation
from zanshin.services.scan_queue import (
    STATUS_QUEUED,
    count_running,
    position_of,
    reclaim_expired_leases,
)
from zanshin.ui.auth import requires_admin
from zanshin.ui.components import empty_state
from zanshin.ui.layout import main_layout
from zanshin.ui.state import BaseState
from zanshin.ui.view_models import AgentRow, QueuedScanRow, format_datetime

CREDENTIALS_OPTIONS = [
    {
        "label": "Local — aucun secret transmis (recommandé)",
        "value": CREDENTIALS_LOCAL,
    },
    {
        "label": "Délégué — le contrôleur envoie la clé de déploiement",
        "value": CREDENTIALS_DELEGATED,
    },
]

class AgentsState(BaseState):
    agents: list[AgentRow] = []
    queue: list[QueuedScanRow] = []
    queued_count: int = 0
    running_count: int = 0
    # True when nothing can pick work up: shown as a warning, because from the
    # operator's side the only symptom is a queue that has silently stopped moving.
    no_worker_available: bool = False
    # Who runs the periodic work (scheduled scans, retention, the outbox relay). Shown
    # because "why did nothing run last night" is a question this answers, and because
    # answering it is why the lease is a table rather than an advisory lock.
    scheduler_owner: str = ""
    scheduler_is_this_instance: bool = False

    create_dialog_open: bool = False
    display_dialog_open: bool = False
    new_name: str = ""
    new_description: str = ""
    new_labels: str = ""
    new_credentials_mode: str = CREDENTIALS_LOCAL
    new_max_concurrent: str = "1"
    created_agent_name: str = ""
    created_key_raw: str = ""

    def set_new_name(self, value: str):
        self.new_name = value

    def set_new_description(self, value: str):
        self.new_description = value

    def set_new_labels(self, value: str):
        self.new_labels = value

    def set_new_credentials_mode(self, value: str):
        self.new_credentials_mode = value

    def set_new_max_concurrent(self, value: str):
        self.new_max_concurrent = value

    @requires_admin
    def load_agents_data(self):
        self.set_current_page("Agents")
        container = get_container()
        try:
            # Opportunistic, and this is one of only two places it happens (the other
            # is the scheduler tick): the observer of a lapsed lease is either an
            # agent looking for work or an operator looking at this page.
            reclaimed = reclaim_expired_leases(container.db)

            agent_service = container.agent_service
            # Registers this process if it has never run before, and refreshes it
            # otherwise — so the page never shows the instance serving it as absent.
            agent_service.ensure_builtin_agent()

            rows = []
            for agent in agent_service.find_all():
                rows.append(AgentRow(
                    id=str(agent.id),
                    name=agent.name,
                    description=agent.description or "",
                    kind=agent.kind,
                    is_builtin=agent.is_builtin,
                    status=agent_service.status_of(agent),
                    enabled=bool(agent.enabled),
                    labels=", ".join(sorted(agent.label_set)) or "—",
                    credentials_mode=agent.credentials_mode,
                    sends_credentials=agent.sends_credentials,
                    max_concurrent=agent_service.capacity_of(agent),
                    running_jobs=count_running(container.db, worker=agent.worker_id),
                    hostname=agent.hostname or "—",
                    platform=agent.platform or "—",
                    version=agent.version or "—",
                    scanner_engine=agent.scanner_engine or "—",
                    last_seen_at=format_datetime(agent.last_seen_at) or "Jamais",
                    created_at=format_datetime(agent.created_at),
                ))
            self.agents = rows
            self.no_worker_available = not any(
                row.status == STATUS_ONLINE for row in rows
            )

            holder = leader_election.current_holder(container.db)
            self.scheduler_is_this_instance = holder == leader_election.INSTANCE_ID
            self.scheduler_owner = holder or ""

            self.queue = self._build_queue(container)
            self.queued_count = sum(1 for row in self.queue if row.status == STATUS_QUEUED)
            self.running_count = len(self.queue) - self.queued_count

            if reclaimed:
                yield self.trigger_toast(
                    f"{len(reclaimed)} scan(s) sans exécutant ont été remis en file d'attente"
                )
        except Exception as e:
            yield self.trigger_toast(f"Erreur de chargement : {str(e)}", is_error=True)
        finally:
            container.db.close()

    def _build_queue(self, container) -> list:
        from zanshin.clock import utcnow

        now = utcnow()
        rows = []
        for scan in container.scan_repository.find_in_flight():
            agent = (
                container.agent_service.find_by_worker_id(scan.claimed_by)
                if scan.claimed_by
                else None
            )
            rows.append(QueuedScanRow(
                scan_id=scan.id,
                target=_target_label(scan),
                status=scan.status,
                position=position_of(container.db, scan) or 0,
                agent_name=(
                    agent.name if agent
                    # A scan whose agent row was deleted keeps its provenance, which
                    # is more useful than pretending nobody ran it.
                    else ("exécutant inconnu" if scan.claimed_by else "—")
                ),
                attempts=scan.attempts or 0,
                lease_expires_at=format_datetime(scan.lease_expires_at, "%H:%M:%S") or "—",
                lease_expired=bool(
                    scan.lease_expires_at is not None and scan.lease_expires_at < now
                ),
                created_at=format_datetime(scan.created_at),
            ))
        return rows

    # --- Creation ---------------------------------------------------------

    def open_create_dialog(self):
        self.new_name = ""
        self.new_description = ""
        self.new_labels = ""
        self.new_credentials_mode = CREDENTIALS_LOCAL
        self.new_max_concurrent = "1"
        self.create_dialog_open = True

    def close_create_dialog(self):
        self.create_dialog_open = False

    def close_display_dialog(self):
        self.display_dialog_open = False
        self.created_key_raw = ""
        self.created_agent_name = ""

    @requires_admin
    def create_agent(self):
        container = get_container()
        try:
            agent, raw_key = container.agent_service.create_remote_agent(
                name=self.new_name,
                description=self.new_description,
                labels=self.new_labels,
                credentials_mode=self.new_credentials_mode,
                max_concurrent=int(self.new_max_concurrent)
                if self.new_max_concurrent.strip().isdigit()
                else 1,
            )
            container.audit_log_service.record(
                AuditOperation.AGENT_CREATED,
                resource_id=str(agent.id),
                description=(
                    f"Agent distant « {agent.name} » enregistré "
                    f"(identifiants : {agent.credentials_mode})"
                ),
                user_id=self.username,
            )
            # Shown once, like any other key: only its hash is stored.
            self.created_agent_name = agent.name
            self.created_key_raw = raw_key
            self.create_dialog_open = False
            self.display_dialog_open = True
            yield self.trigger_toast(f"Agent « {agent.name} » enregistré")
            yield AgentsState.load_agents_data(self)
        except ValueError as e:
            yield self.trigger_toast(str(e), is_error=True)
        except Exception as e:
            yield self.trigger_toast(f"Erreur d'enregistrement : {str(e)}", is_error=True)
        finally:
            container.db.close()

    # --- Lifecycle --------------------------------------------------------

    @requires_admin
    def toggle_agent(self, agent_id: str, enabled: bool):
        container = get_container()
        try:
            agent = container.agent_service.set_enabled(agent_id, enabled)
            container.audit_log_service.record(
                AuditOperation.AGENT_UPDATED,
                resource_id=agent_id,
                description=f"Agent « {agent.name} » {'activé' if enabled else 'désactivé'}",
                user_id=self.username,
            )
            if agent.is_builtin and not enabled:
                yield self.trigger_toast(
                    "Cette instance n'exécutera plus de scans : ils attendront un agent distant."
                )
            else:
                yield self.trigger_toast(
                    f"Agent « {agent.name} » {'activé' if enabled else 'désactivé'}"
                )
            yield AgentsState.load_agents_data(self)
        except ValueError as e:
            yield self.trigger_toast(str(e), is_error=True)
        finally:
            container.db.close()

    @requires_admin
    def set_credentials_mode(self, agent_id: str, mode: str):
        container = get_container()
        try:
            agent = container.agent_service.update_agent(agent_id, credentials_mode=mode)
            container.audit_log_service.record(
                AuditOperation.AGENT_UPDATED,
                resource_id=agent_id,
                description=f"Mode d'identifiants de « {agent.name} » : {mode}",
                user_id=self.username,
            )
            if mode == CREDENTIALS_DELEGATED:
                yield self.trigger_toast(
                    "Les clés de déploiement seront transmises à cet agent — "
                    "uniquement en HTTPS, et chaque remise est auditée."
                )
            else:
                yield self.trigger_toast("Aucun secret ne sera transmis à cet agent")
            yield AgentsState.load_agents_data(self)
        except ValueError as e:
            yield self.trigger_toast(str(e), is_error=True)
        finally:
            container.db.close()

    @requires_admin
    def delete_agent(self, agent_id: str):
        container = get_container()
        try:
            agent = container.agent_service.find_by_id(agent_id)
            name = agent.name if agent else agent_id
            container.agent_service.delete_agent(agent_id)
            container.audit_log_service.record(
                AuditOperation.AGENT_DELETED,
                resource_id=agent_id,
                description=f"Agent « {name} » supprimé",
                user_id=self.username,
            )
            yield self.trigger_toast(f"Agent « {name} » supprimé")
            yield AgentsState.load_agents_data(self)
        except ValueError as e:
            yield self.trigger_toast(str(e), is_error=True)
        finally:
            container.db.close()

def _target_label(scan) -> str:
    if scan.container_id and scan.container:
        return scan.container.image_string
    if scan.repository:
        return scan.repository.name or scan.repository.url
    return f"scan #{scan.id}"

def _status_badge(row: AgentRow) -> rx.Component:
    return rx.badge(
        rx.cond(
            row.status == STATUS_ONLINE,
            "en ligne",
            rx.cond(row.status == STATUS_DISABLED, "désactivé", "hors ligne"),
        ),
        color_scheme=rx.cond(
            row.status == STATUS_ONLINE,
            "green",
            rx.cond(row.status == STATUS_DISABLED, "gray", "orange"),
        ),
        variant="solid",
    )

def _agent_row(row: AgentRow) -> rx.Component:
    return rx.table.row(
        rx.table.row_header_cell(
            rx.vstack(
                rx.hstack(
                    rx.text(row.name, weight="medium"),
                    rx.cond(
                        row.is_builtin,
                        rx.badge("intégré", color_scheme="cyan", variant="surface"),
                    ),
                    spacing="2",
                    align="center",
                ),
                rx.text(row.hostname, size="1", color="var(--slate-10)"),
                spacing="0",
            )
        ),
        rx.table.cell(_status_badge(row)),
        rx.table.cell(
            rx.hstack(
                rx.text(f"{row.running_jobs} / {row.max_concurrent}"),
                rx.cond(
                    row.max_concurrent == 0,
                    rx.tooltip(
                        rx.icon(tag="circle-slash", size=14, color="var(--slate-10)"),
                        content="Cet agent ne prendra aucun scan",
                    ),
                ),
                spacing="2",
                align="center",
            )
        ),
        rx.table.cell(row.labels),
        rx.table.cell(
            rx.hstack(
                rx.badge(
                    rx.cond(row.sends_credentials, "délégué", "local"),
                    color_scheme=rx.cond(row.sends_credentials, "amber", "green"),
                    variant="soft",
                ),
                rx.cond(
                    row.sends_credentials,
                    rx.tooltip(
                        rx.icon(tag="key-round", size=14, color="var(--amber-9)"),
                        content=(
                            "Le contrôleur transmet la clé de déploiement à cet agent "
                            "(HTTPS obligatoire, chaque remise est auditée)."
                        ),
                    ),
                ),
                spacing="2",
                align="center",
            )
        ),
        rx.table.cell(
            rx.vstack(
                rx.text(row.scanner_engine, size="2"),
                rx.text(row.platform, size="1", color="var(--slate-10)"),
                spacing="0",
            )
        ),
        rx.table.cell(row.last_seen_at),
        rx.table.cell(
            rx.hstack(
                rx.tooltip(
                    rx.switch(
                        checked=row.enabled,
                        on_change=lambda value: AgentsState.toggle_agent(row.id, value),
                    ),
                    content="Activer / désactiver",
                ),
                rx.cond(
                    ~row.is_builtin,
                    rx.hstack(
                        rx.tooltip(
                            rx.button(
                                rx.icon(tag="key-round"),
                                size="2",
                                variant="soft",
                                color_scheme=rx.cond(row.sends_credentials, "green", "amber"),
                                on_click=lambda: AgentsState.set_credentials_mode(
                                    row.id,
                                    rx.cond(
                                        row.sends_credentials,
                                        CREDENTIALS_LOCAL,
                                        CREDENTIALS_DELEGATED,
                                    ),
                                ),
                            ),
                            content="Basculer le mode d'identifiants",
                        ),
                        rx.tooltip(
                            rx.button(
                                rx.icon(tag="trash"),
                                size="2",
                                color_scheme="red",
                                variant="soft",
                                on_click=lambda: AgentsState.delete_agent(row.id),
                            ),
                            content="Supprimer",
                        ),
                        spacing="2",
                    ),
                ),
                spacing="3",
                align="center",
            )
        ),
    )

def _queue_row(row: QueuedScanRow) -> rx.Component:
    return rx.table.row(
        rx.table.row_header_cell(f"#{row.scan_id}"),
        rx.table.cell(row.target),
        rx.table.cell(
            rx.hstack(
                rx.badge(
                    rx.cond(row.status == STATUS_QUEUED, "en file", "en cours"),
                    color_scheme=rx.cond(row.status == STATUS_QUEUED, "gray", "blue"),
                ),
                rx.cond(
                    row.position > 0,
                    rx.text(f"n° {row.position}", size="1", color="var(--slate-10)"),
                ),
                spacing="2",
                align="center",
            )
        ),
        rx.table.cell(row.agent_name),
        rx.table.cell(
            rx.cond(
                row.lease_expired,
                rx.tooltip(
                    rx.badge("bail expiré", color_scheme="red"),
                    content=(
                        "Cet exécutant ne répond plus : le scan repartira en file "
                        "d'attente au prochain passage."
                    ),
                ),
                rx.text(row.lease_expires_at, size="2"),
            )
        ),
        rx.table.cell(
            rx.cond(
                row.attempts > 1,
                rx.badge(f"{row.attempts}", color_scheme="amber"),
                rx.text(row.attempts.to_string(), size="2"),
            )
        ),
        rx.table.cell(row.created_at),
    )

def agents_page() -> rx.Component:
    content = rx.vstack(
        rx.hstack(
            rx.text(
                "Les scans sont exécutés par des agents. Cette instance en est un — "
                "désactivez-le pour que tout parte sur des machines distantes.",
                size="2",
                color="var(--slate-10)",
            ),
            rx.spacer(),
            rx.button(
                "Ajouter un agent distant",
                rx.icon(tag="plus"),
                color_scheme="cyan",
                on_click=AgentsState.open_create_dialog,
            ),
            width="100%",
            align="center",
        ),

        rx.cond(
            AgentsState.no_worker_available & (AgentsState.queued_count > 0),
            rx.callout(
                "Aucun agent n'est en ligne : les scans en file d'attente ne "
                "démarreront pas tant qu'un agent ne se connectera pas.",
                icon="triangle-alert",
                color_scheme="red",
                size="1",
                width="100%",
            ),
        ),

        # --- Agents ---
        rx.box(
            rx.table.root(
                rx.table.header(
                    rx.table.row(
                        rx.table.column_header_cell("Agent"),
                        rx.table.column_header_cell("État"),
                        rx.table.column_header_cell("Scans"),
                        rx.table.column_header_cell("Labels"),
                        rx.table.column_header_cell("Identifiants git"),
                        rx.table.column_header_cell("Moteur"),
                        rx.table.column_header_cell("Vu à"),
                        rx.table.column_header_cell("Actions"),
                    )
                ),
                rx.table.body(rx.foreach(AgentsState.agents, _agent_row)),
                width="100%",
            ),
            width="100%",
            class_name="p-6 rounded-xl bg-slate-2 border border-slate-4 shadow-sm w-full",
        ),

        # --- Queue ---
        rx.vstack(
            rx.hstack(
                rx.heading("File d'attente", size="4", weight="bold"),
                rx.badge(
                    f"{AgentsState.queued_count} en attente", color_scheme="gray"
                ),
                rx.badge(f"{AgentsState.running_count} en cours", color_scheme="blue"),
                rx.spacer(),
                # The periodic work has exactly one owner across a fleet; naming it here
                # is what makes "nothing ran last night" diagnosable.
                rx.cond(
                    AgentsState.scheduler_owner != "",
                    rx.tooltip(
                        rx.badge(
                            rx.cond(
                                AgentsState.scheduler_is_this_instance,
                                "scans planifiés : cette instance",
                                "scans planifiés : autre instance",
                            ),
                            color_scheme=rx.cond(
                                AgentsState.scheduler_is_this_instance, "cyan", "gray"
                            ),
                            variant="surface",
                        ),
                        content=(
                            "Les scans planifiés, la rétention et le relais des "
                            "notifications n'ont qu'un seul propriétaire : sans cela, "
                            "deux instances scanneraient chaque cible deux fois."
                        ),
                    ),
                ),
                spacing="3",
                align="center",
                width="100%",
            ),
            rx.cond(
                AgentsState.queue.length() > 0,
                rx.table.root(
                    rx.table.header(
                        rx.table.row(
                            rx.table.column_header_cell("Scan"),
                            rx.table.column_header_cell("Cible"),
                            rx.table.column_header_cell("État"),
                            rx.table.column_header_cell("Exécutant"),
                            rx.table.column_header_cell("Bail jusqu'à"),
                            rx.table.column_header_cell("Tentatives"),
                            rx.table.column_header_cell("Demandé le"),
                        )
                    ),
                    rx.table.body(rx.foreach(AgentsState.queue, _queue_row)),
                    width="100%",
                ),
                empty_state(
                    "inbox",
                    "Rien en attente",
                    "Les scans lancés depuis Dépôts ou Conteneurs apparaîtront ici.",
                ),
            ),
            width="100%",
            spacing="3",
            class_name="p-6 rounded-xl bg-slate-2 border border-slate-4 shadow-sm w-full",
        ),

        # --- Creation dialog ---
        rx.dialog.root(
            rx.dialog.content(
                rx.dialog.title("Ajouter un agent distant"),
                rx.dialog.description(
                    "Une clé API à portée « agent » sera émise avec lui : elle ne "
                    "permet que de réclamer des scans et d'en remonter les résultats."
                ),
                rx.vstack(
                    rx.text("Nom", size="2", weight="bold"),
                    rx.input(
                        placeholder="Ex : paris-01",
                        value=AgentsState.new_name,
                        on_change=AgentsState.set_new_name,
                        class_name="w-full",
                    ),
                    rx.text("Description", size="2", weight="bold"),
                    rx.input(
                        placeholder="Ex : runner du segment interne",
                        value=AgentsState.new_description,
                        on_change=AgentsState.set_new_description,
                        class_name="w-full",
                    ),
                    rx.text("Labels (séparés par des virgules)", size="2", weight="bold"),
                    rx.input(
                        placeholder="Ex : linux, registre-interne",
                        value=AgentsState.new_labels,
                        on_change=AgentsState.set_new_labels,
                        class_name="w-full",
                    ),
                    rx.text("Scans simultanés", size="2", weight="bold"),
                    rx.input(
                        type="number",
                        value=AgentsState.new_max_concurrent,
                        on_change=AgentsState.set_new_max_concurrent,
                        class_name="w-full",
                    ),
                    rx.text("Identifiants git", size="2", weight="bold"),
                    rx.select.root(
                        rx.select.trigger(),
                        rx.select.content(
                            rx.select.group(
                                rx.foreach(
                                    CREDENTIALS_OPTIONS,
                                    lambda opt: rx.select.item(
                                        opt["label"], value=opt["value"]
                                    ),
                                )
                            )
                        ),
                        value=AgentsState.new_credentials_mode,
                        on_change=AgentsState.set_new_credentials_mode,
                        width="100%",
                    ),
                    rx.cond(
                        AgentsState.new_credentials_mode == CREDENTIALS_DELEGATED,
                        rx.callout(
                            "Le contrôleur enverra la clé de déploiement déchiffrée à "
                            "cet agent, à chaque scan. Réservez ce mode à une machine "
                            "de confiance, servez le contrôleur en HTTPS (sans quoi la "
                            "remise est refusée) et sachez qu'un agent compromis "
                            "conserve la clé jusqu'à sa rotation.",
                            icon="key-round",
                            color_scheme="amber",
                            size="1",
                        ),
                        rx.callout(
                            "Aucun secret ne quitte le contrôleur : cette machine doit "
                            "avoir son propre accès git aux dépôts qu'elle scanne.",
                            icon="shield-check",
                            color_scheme="green",
                            size="1",
                        ),
                    ),
                    spacing="2",
                    class_name="mt-4 w-full",
                ),
                rx.hstack(
                    rx.dialog.close(
                        rx.button(
                            "Annuler",
                            variant="soft",
                            color_scheme="gray",
                            on_click=AgentsState.close_create_dialog,
                        )
                    ),
                    rx.button(
                        "Enregistrer", on_click=AgentsState.create_agent, color_scheme="green"
                    ),
                    spacing="3",
                    class_name="mt-6 justify-end",
                ),
                class_name="max-w-lg w-full",
            ),
            open=AgentsState.create_dialog_open,
        ),

        # --- Key + launch command, shown once ---
        rx.dialog.root(
            rx.dialog.content(
                rx.dialog.title("Agent enregistré"),
                rx.dialog.description(
                    "Copiez cette clé maintenant : elle ne sera plus affichée."
                ),
                rx.vstack(
                    rx.input(
                        value=AgentsState.created_key_raw,
                        read_only=True,
                        class_name="w-full font-mono",
                    ),
                    rx.text("Commande de lancement", size="2", weight="bold"),
                    rx.code_block(
                        "ZANSHIN_URL=https://<votre-instance> \\\n"
                        f"ZANSHIN_AGENT_TOKEN={AgentsState.created_key_raw} \\\n"
                        "python -m zanshin.agent",
                        language="bash",
                        wrap_long_lines=True,
                        width="100%",
                    ),
                    rx.text(
                        "Cette machine a besoin de Docker et d'un accès git aux dépôts "
                        "scannés. Voir docker-compose.agent.yml pour la variante "
                        "conteneurisée.",
                        size="1",
                        color="var(--slate-10)",
                    ),
                    spacing="2",
                    class_name="mt-4 w-full",
                ),
                rx.hstack(
                    rx.button(
                        "J'ai copié la clé",
                        on_click=AgentsState.close_display_dialog,
                        color_scheme="cyan",
                    ),
                    class_name="mt-6 justify-end w-full",
                ),
                class_name="max-w-xl w-full",
            ),
            open=AgentsState.display_dialog_open,
        ),

        width="100%",
        spacing="4",
        on_mount=AgentsState.load_agents_data,
    )

    return main_layout(content, "Agents")
