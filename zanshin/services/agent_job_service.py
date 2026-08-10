"""Handing work to a remote agent, and taking its results back.

The business half of the agent API (`zanshin/api/agents.py`), kept out of the
route handlers for the reason stated in that package: a route validates input and
calls a service, so that the same decisions apply however they are reached.

Three decisions live here, and each is a security boundary rather than a
convenience:

1. **What goes into a task.** A repository URL and a branch, and a deploy key
   *only* if the agent's `credentials_mode` says so and the transport is
   encrypted. Everything else stays on the control plane.
2. **Who may report on a job.** The agent that holds the lease, and nobody else —
   otherwise a compromised agent could overwrite another's results, which means
   editing the finding set a gate is evaluated against (décision 0003).
3. **What a retry does.** Nothing, the second time. The marker and the effect
   commit together (see `ProcessedMessage`).
"""
import logging
import os
from typing import Optional, Tuple

from zanshin.models.agent import Agent
from zanshin.models.scan import Scan
from zanshin.scan_contract import (
    CONTRACT_VERSION,
    TARGET_CONTAINER,
    TARGET_REPOSITORY,
    ScanArtifacts,
    ScanTask,
)
from zanshin.services.audit_log_service import AuditOperation
from zanshin.services.scan_queue import claim_next, still_owned

logger = logging.getLogger(__name__)

# Refuse to put deploy key material in a task travelling over plain HTTP. Set to
# "true" only to try the delegated mode locally: the key is the credential to
# somebody's source tree, and the whole point of décision 0003's opt-in is that
# choosing it is deliberate — silently downgrading it to cleartext would undo
# that.
ALLOW_INSECURE_CREDENTIALS = (
    os.getenv("ZANSHIN_ALLOW_INSECURE_AGENT_CREDENTIALS", "false").lower() == "true"
)

OUTCOME_APPLIED = "applied"
OUTCOME_DUPLICATE = "duplicate"

MESSAGE_TYPE_SCAN_RESULT = "agent.scan_result"


class InsecureCredentialTransport(RuntimeError):
    """A task needs a deploy key, and the agent asked for it over plain HTTP."""


class AgentJobService:
    def __init__(
        self,
        agent_service,
        scan_repository,
        ssh_key_service,
        scan_ingestor,
        processed_message_repository,
        audit_log_service=None,
    ):
        self.agent_service = agent_service
        self.scan_repository = scan_repository
        self.ssh_key_service = ssh_key_service
        self.scan_ingestor = scan_ingestor
        self.processed_message_repository = processed_message_repository
        self.audit_log_service = audit_log_service

    # --- Handing out work -------------------------------------------------

    def available_capacity(self, db, agent: Agent) -> int:
        from zanshin.services.scan_queue import count_running

        return self.agent_service.capacity_of(agent) - count_running(
            db, worker=agent.worker_id
        )

    def claim_task(self, db, agent: Agent, secure_transport: bool = True) -> Optional[ScanTask]:
        """Claim one queued scan for `agent` and return it as a task.

        One at a time, even when the agent has spare capacity: the agent asks
        again when it is ready, which is the flow control décision 0003 relies on —
        the control plane never has to guess how busy an agent is.

        A claim that cannot be turned into a usable task (a repository row deleted
        between queueing and claiming, or a key that must not travel over this
        transport) is released rather than left running: the scan goes back to
        `pending` for someone else, instead of silently holding a lease nobody
        will ever report on.
        """
        if self.available_capacity(db, agent) <= 0:
            return None

        claimed = claim_next(db, limit=1, worker=agent.worker_id)
        if not claimed:
            return None

        scan = claimed[0]
        try:
            return self.build_task(db, agent, scan, secure_transport=secure_transport)
        except Exception:
            logger.exception(
                "Could not build a task for scan %s; returning it to the queue", scan.id
            )
            self._release(db, scan)
            raise

    def build_task(
        self, db, agent: Agent, scan: Scan, secure_transport: bool = True
    ) -> ScanTask:
        if scan.container_id is not None:
            return ScanTask(
                scan_id=scan.id,
                kind=TARGET_CONTAINER,
                image=scan.container.image_string,
                branch=scan.branch or scan.container.tag or "latest",
            )

        repo = scan.repository
        if repo is None:
            raise ValueError(f"Le scan {scan.id} ne référence plus aucun dépôt.")

        private_key = None
        if repo.ssh_key_id and agent.sends_credentials:
            if not secure_transport and not ALLOW_INSECURE_CREDENTIALS:
                raise InsecureCredentialTransport(
                    "Refus de transmettre une clé de déploiement en clair : l'agent "
                    f"« {agent.name} » est en mode « délégué » mais joint le contrôleur "
                    "en HTTP. Utilisez HTTPS, ou repassez l'agent en mode « local » "
                    "pour qu'il utilise ses propres identifiants git."
                )
            private_key = self.ssh_key_service.get_decrypted_key(repo.ssh_key_id)
            self._audit_credential_delivery(agent, scan, repo)

        return ScanTask(
            scan_id=scan.id,
            kind=TARGET_REPOSITORY,
            repo_url=repo.url,
            branch=scan.branch or repo.branch or "main",
            sub_path=scan.sub_path or "",
            ssh_private_key=private_key,
            collect_code_sample=self.scan_ingestor.wants_code_sample(is_container=False),
            # Décidé ici et pas par l'agent : le réglage vit en base, et un agent n'a
            # pas de base (décision 0003). L'oubli de cette ligne faisait que les
            # agents distants n'exécutaient jamais Semgrep, quel que soit le réglage —
            # sans erreur nulle part, puisque `run_sast` retombait sur son défaut
            # `False` et que le contrat traite l'absence de résultat SAST comme
            # « l'étape n'a pas tourné », ce qui est vrai et laisse le backlog intact.
            run_sast=self.scan_ingestor.wants_sast(is_container=False),
        )

    def _release(self, db, scan: Scan) -> None:
        scan.status = "pending"
        scan.claimed_by = None
        scan.claimed_at = None
        scan.lease_expires_at = None
        db.commit()

    def _audit_credential_delivery(self, agent: Agent, scan: Scan, repo) -> None:
        """One trail entry per delivered key.

        Not optional, and not merely a log line: in `delegated` mode a key leaves
        the control plane, and if an agent is later found to be compromised the
        only answerable question is *which* keys it received and when. décision 0003
        makes this a condition of the mode existing at all.
        """
        if not self.audit_log_service:
            return
        self.audit_log_service.record(
            AuditOperation.AGENT_CREDENTIAL_SENT,
            resource_id=str(repo.ssh_key_id),
            description=(
                f"Clé de déploiement transmise à l'agent « {agent.name} » "
                f"pour le scan {scan.id} du dépôt {repo.id}"
            ),
            user_id=f"agent:{agent.name}",
        )

    # --- Taking results back ----------------------------------------------

    def find_owned_scan(self, db, agent: Agent, scan_id: int) -> Scan:
        """The scan `agent` is allowed to act on, or raise.

        Ownership is checked here rather than trusted from the request: the scan id
        is a small integer an agent could simply guess, and a report on somebody
        else's scan is a report on findings a gate will be evaluated against.

        Stricter than `scan_queue.still_owned`, deliberately. That function accepts a
        scan with no recorded owner, because the alternative would strand rows
        claimed before ownership existed — a reasonable allowance for the built-in
        agent, which is the process that claimed them. Extended to a remote agent it
        would be a hole: any agent could post results for any *queued* scan, at any
        time, without ever having been given the work. So here the claim must be
        explicit, and it must be this agent's.
        """
        scan = self.scan_repository.find_by_id(scan_id)
        if scan is None:
            raise LookupError(f"Scan {scan_id} introuvable.")
        if scan.claimed_by != agent.worker_id:
            raise PermissionError(
                f"Le scan {scan_id} n'est pas attribué à cet agent."
            )
        if not still_owned(db, scan_id, agent.worker_id):
            raise PermissionError(
                f"Le scan {scan_id} n'est plus attribué à cet agent : le travail a été réattribué."
            )
        return scan

    def apply_success(
        self, db, agent: Agent, scan: Scan, artifacts: ScanArtifacts, message_id: str
    ) -> Tuple[str, Scan]:
        """Ingest a successful report, exactly once."""
        if self.processed_message_repository.was_processed(message_id):
            logger.info(
                "Ignoring a replayed result for scan %s from agent '%s' (message %s)",
                scan.id, agent.name, message_id,
            )
            return OUTCOME_DUPLICATE, scan

        # Staged, not committed: `ingest` commits, and that single commit is what
        # makes the marker and the results atomic. Committing here first would
        # leave a marker for work that then failed to be applied — a scan stuck
        # `scanning` that no retry could ever fix.
        self.processed_message_repository.mark(
            message_id, MESSAGE_TYPE_SCAN_RESULT, agent_id=agent.id
        )
        self.scan_ingestor.ingest(db, scan, artifacts)
        return OUTCOME_APPLIED, scan

    def apply_failure(
        self, db, agent: Agent, scan: Scan, error: str, message_id: str
    ) -> Tuple[str, Scan]:
        if self.processed_message_repository.was_processed(message_id):
            return OUTCOME_DUPLICATE, scan
        self.processed_message_repository.mark(
            message_id, MESSAGE_TYPE_SCAN_RESULT, agent_id=agent.id
        )
        self.scan_ingestor.record_failure(
            db, scan, f"[{agent.name}] {error}" if error else f"[{agent.name}] Échec du scan"
        )
        return OUTCOME_APPLIED, scan

    # --- Identity ---------------------------------------------------------

    def check_contract(self, reported_version: Optional[str]) -> None:
        """Refuse an agent speaking a contract this control plane does not know.

        Two artefacts deployed separately will eventually differ in version
        (docs/architecture/04). Failing here, with both numbers in the message, is the
        difference between "upgrade your agent" and a `KeyError` on a missing field
        halfway through ingesting a result.
        """
        if reported_version and reported_version != CONTRACT_VERSION:
            raise ValueError(
                f"Version de contrat incompatible : l'agent parle « {reported_version} », "
                f"ce contrôleur attend « {CONTRACT_VERSION} ». Mettez à jour l'agent "
                "(ou le contrôleur) pour que les deux correspondent."
            )
