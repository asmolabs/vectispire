"""The endpoints a remote agent talks to.

Four routes, all requiring the `agent` scope and nothing else: announce yourself,
ask for work, say you are still alive, report what happened. An agent can do no
more than that — it cannot read the issue history, export a VEX document or queue
a scan, because its key carries no other scope.

**Why the agent polls instead of being pushed to** (décision 0003): it needs no
inbound port and no database credentials, so it works behind NAT, and it asks for
work only when it has capacity — which is flow control that costs nothing to
implement. The cost is a long-poll, and 30 seconds of waiting on a scan that takes
minutes is not a latency problem.

The routes are thin, like the rest of `zanshin/api/`: the decisions (what goes in
a task, who may report on a job, what a retry does) are in `AgentJobService`.
"""
import asyncio
import json
import logging
import os
import threading
import time
from typing import Dict, Optional, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from starlette.concurrency import run_in_threadpool

from zanshin.api.deps import get_container, require_scope
from zanshin.api.schemas import (
    AgentHello,
    AgentIdentity,
    AgentProgress,
    AgentResult,
    AgentResultAck,
)
from zanshin.container import IoCContainer
from zanshin.models.agent import Agent
from zanshin.models.api_key import SCOPE_AGENT, ApiKey
from zanshin.scan_contract import CONTRACT_VERSION, ScanArtifacts, ScanTask
from zanshin.services.agent_job_service import (
    OUTCOME_APPLIED,
    OUTCOME_DUPLICATE,
    InsecureCredentialTransport,
)
from zanshin.services.audit_log_service import AuditOperation
from zanshin.services.scan_queue import LEASE_SECONDS, renew_lease

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/agents", tags=["agents"])

# Longest a claim request may wait for work before answering "nothing yet". Kept
# under the usual 60s proxy read timeout: an agent whose long-poll is cut by an
# intermediary cannot tell that apart from a controller that died, and would log
# an error every poll of an idle system.
MAX_POLL_WAIT_SECONDS = int(os.getenv("ZANSHIN_AGENT_MAX_POLL_WAIT_SECONDS", "30"))
# How often, inside a long-poll, to look again. One second: the queue is a table,
# not an event source, and a scan that waits an extra second to start is not a
# problem worth a notification mechanism for.
POLL_CHECK_INTERVAL_SECONDS = 1.0
# What the agent is told to do between heartbeats. Comfortably inside
# `LEASE_SECONDS` so several may be missed before the queue reclaims the work.
HEARTBEAT_SECONDS = max(15, LEASE_SECONDS // 20)

# Assembly buffer for results that arrived in slices, keyed by (agent, upload id).
# In memory, per process — the same choice, for the same reason, as the API rate
# limiter and the login throttle: this control plane is single-process (see
# docs/architecture/04), and a table would mean writing megabytes twice. An
# interrupted upload is therefore lost on restart, which is correct: the agent
# still holds the lease and retries the whole report.
_CHUNK_TTL_SECONDS = 600
_chunks: Dict[Tuple[str, str], Tuple[float, Dict[int, str], int]] = {}
_chunks_lock = threading.Lock()


def require_agent(
    container: IoCContainer = Depends(get_container),
    api_key: ApiKey = Depends(require_scope(SCOPE_AGENT)),
) -> Tuple[Agent, IoCContainer]:
    """Resolve the calling credential to an agent, and mark it as alive.

    Identity comes from the key, never from the request body: an agent that could
    name itself could claim to be another one — including one in `delegated` mode,
    which is how it would talk the control plane into handing over a deploy key.
    """
    agent = container.agent_service.find_by_api_key_id(api_key.id)
    if agent is None:
        # The key is valid and carries the scope, but no agent is bound to it.
        # 403 rather than 401: retrying with the same credential will not help.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Cette clé n'est rattachée à aucun agent. Créez l'agent depuis la page "
                "Agents : la clé y est émise avec lui."
            ),
        )
    if not agent.enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"L'agent « {agent.name} » est désactivé.",
        )
    return agent, container


def _is_secure_transport(request: Request, forwarded_proto: Optional[str]) -> bool:
    """Whether this request reached us over TLS.

    `X-Forwarded-Proto` is honoured because the intended deployment puts a reverse
    proxy in front, where the application itself only ever sees plain HTTP. That
    header is trivially forgeable by whoever can reach this port directly — which
    is why it decides *only* whether a deploy key may travel, a decision the
    operator has already had to opt into per agent (décision 0003).
    """
    if (forwarded_proto or "").split(",")[0].strip().lower() == "https":
        return True
    return request.url.scheme == "https"


@router.post("/hello", response_model=AgentIdentity)
def hello(
    body: AgentHello,
    resolved=Depends(require_agent),
):
    """Announce an agent and read back how it should behave.

    Also the health check an operator runs first: if this answers, the URL, the
    key, the scope and the agent row are all correct, which is most of what can be
    misconfigured.
    """
    agent, container = resolved
    try:
        container.agent_job_service.check_contract(body.contract_version)
    except ValueError as e:
        # 409, not 400: the request is well-formed, the two sides simply disagree
        # about the protocol — and the fix is a deployment, not a different call.
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e)) from e

    container.agent_service.touch(agent, body.model_dump())
    logger.info("Agent '%s' checked in from %s", agent.name, agent.hostname or "unknown host")
    return _identity(container, agent)


@router.get("/jobs", response_model=Optional[ScanTask], response_model_exclude_none=True)
async def claim_job(
    request: Request,
    response: Response,
    wait: int = 0,
    x_forwarded_proto: Optional[str] = Header(default=None),
    resolved=Depends(require_agent),
):
    """Claim one queued scan, waiting up to `wait` seconds for one to appear.

    204 when there is nothing to do — an empty body rather than an empty object, so
    an agent's "is there work?" is a status check and not a parse.

    Asynchronous, and the database work runs in a thread: a synchronous handler
    sleeping for thirty seconds would hold one of the server's worker threads for
    the whole poll, so a handful of idle agents could starve the UI.
    """
    agent, container = resolved
    secure = _is_secure_transport(request, x_forwarded_proto)
    deadline = time.monotonic() + max(0, min(wait, MAX_POLL_WAIT_SECONDS))

    while True:
        try:
            task = await run_in_threadpool(
                container.agent_job_service.claim_task,
                container.db,
                agent,
                secure,
            )
        except InsecureCredentialTransport as e:
            # The scan has already been returned to the queue; refusing loudly is
            # the point — silently scanning without the key would produce a clone
            # failure that looks like a network problem.
            raise HTTPException(status_code=status.HTTP_412_PRECONDITION_FAILED, detail=str(e)) from e
        except Exception as e:
            logger.exception("Could not hand a job to agent '%s'", agent.name)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e)
            ) from e

        if task is not None:
            logger.info("Scan %s handed to agent '%s'", task.scan_id, agent.name)
            return task

        if time.monotonic() >= deadline:
            response.status_code = status.HTTP_204_NO_CONTENT
            return None

        await asyncio.sleep(POLL_CHECK_INTERVAL_SECONDS)
        # Otherwise this session keeps serving the snapshot it read on the first
        # pass, and the poll would never see a scan queued while it waited.
        await run_in_threadpool(container.db.expire_all)


@router.post("/jobs/{scan_id}/heartbeat", status_code=status.HTTP_204_NO_CONTENT)
def heartbeat(
    scan_id: int,
    body: AgentProgress,
    resolved=Depends(require_agent),
):
    """Renew the lease on a job in progress.

    409 when the lease is no longer held: the agent has lost the work (its silence
    outlasted the lease and the queue moved on) and should stop, rather than
    finishing a scan whose result will be refused.
    """
    agent, container = resolved
    container.agent_service.touch(agent)

    if not renew_lease(container.db, scan_id, agent.worker_id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Le bail sur le scan {scan_id} n'est plus détenu par cet agent : "
                "le travail a été réattribué."
            ),
        )
    if body.message:
        logger.info("Scan %s on agent '%s': %s", scan_id, agent.name, body.message)
    return None


@router.post("/jobs/{scan_id}/result", response_model=AgentResultAck)
def submit_result(
    scan_id: int,
    body: AgentResult,
    resolved=Depends(require_agent),
):
    """Report a finished job: its artifacts, or why it failed.

    Idempotent on `message_id`, because delivery is at-least-once in this direction
    too — an agent that loses the response has no way to know whether the report
    landed, so its only safe move is to send it again (see `ProcessedMessage`).
    """
    agent, container = resolved
    container.agent_service.touch(agent)
    service = container.agent_job_service

    if not body.message_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="'message_id' est obligatoire : c'est lui qui rend un réessai sans effet.",
        )

    try:
        scan = service.find_owned_scan(container.db, agent, scan_id)
    except LookupError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e)) from e
    except PermissionError as e:
        # Audited: an agent reporting on a scan it does not hold is either a bug or
        # an attempt to rewrite the finding set a gate reads.
        container.audit_log_service.record(
            AuditOperation.ACCESS_DENIED,
            resource_id=str(scan_id),
            description=f"L'agent « {agent.name} » a tenté de remonter un scan qu'il ne détient pas",
            user_id=f"agent:{agent.name}",
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e)) from e

    if body.status == "failed":
        outcome, _ = service.apply_failure(
            container.db, agent, scan, body.error or "", body.message_id
        )
        _audit_submission(container, agent, scan, outcome, failed=True)
        return AgentResultAck(scan_id=scan.id, outcome=outcome)

    payload, chunks_received = _assemble(agent, body)
    if payload is None:
        # More slices expected; the lease is still renewed by the heartbeat, so
        # nothing expires while a large SBOM is being uploaded.
        return AgentResultAck(
            scan_id=scan.id, outcome="chunk_received", chunks_received=chunks_received
        )

    try:
        artifacts = ScanArtifacts.model_validate(payload)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Artefacts illisibles : {e}",
        ) from e

    outcome, _ = service.apply_success(container.db, agent, scan, artifacts, body.message_id)
    _audit_submission(container, agent, scan, outcome, failed=False)
    return AgentResultAck(scan_id=scan.id, outcome=outcome)


def _audit_submission(container, agent: Agent, scan, outcome: str, failed: bool) -> None:
    if outcome == OUTCOME_DUPLICATE:
        # A replay changed nothing, so recording it as a submission would make the
        # trail say the finding set was rewritten when it was not.
        return
    container.audit_log_service.record(
        AuditOperation.AGENT_RESULT_SUBMITTED,
        resource_id=str(scan.id),
        description=(
            f"Résultat {'d’échec ' if failed else ''}du scan {scan.id} "
            f"remonté par l'agent « {agent.name} »"
        ),
        user_id=f"agent:{agent.name}",
    )


def _identity(container: IoCContainer, agent: Agent) -> AgentIdentity:
    return AgentIdentity(
        agent_id=agent.worker_id,
        name=agent.name,
        labels=sorted(agent.label_set),
        credentials_mode=agent.credentials_mode,
        max_concurrent=container.agent_service.capacity_of(agent),
        enabled=agent.enabled,
        contract_version=CONTRACT_VERSION,
        poll_wait_seconds=MAX_POLL_WAIT_SECONDS,
        heartbeat_seconds=HEARTBEAT_SECONDS,
    )


def _assemble(agent: Agent, body: AgentResult):
    """Return the complete artifacts payload, or `None` if slices are still missing.

    Reassembles the serialized JSON rather than merging structures: the agent
    splits a string and does not have to understand what it is splitting, and a
    slice that arrives twice simply overwrites its own index.
    """
    if body.chunk is None:
        return body.artifacts or {}, None

    chunk = body.chunk
    if chunk.count <= 0 or not (0 <= chunk.index < chunk.count):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Fragment invalide : index {chunk.index} sur {chunk.count}.",
        )

    key = (agent.worker_id, chunk.upload_id)
    now = time.monotonic()
    with _chunks_lock:
        # Expire abandoned uploads on the way past, so a fleet of agents that keep
        # dying mid-upload cannot grow this dictionary without bound.
        for stale_key in [k for k, (seen, _, _) in _chunks.items() if now - seen > _CHUNK_TTL_SECONDS]:
            del _chunks[stale_key]

        _seen, parts, count = _chunks.get(key, (now, {}, chunk.count))
        parts[chunk.index] = chunk.data
        _chunks[key] = (now, parts, chunk.count)
        if len(parts) < chunk.count:
            return None, len(parts)
        del _chunks[key]

    joined = "".join(parts[index] for index in range(chunk.count))
    try:
        return json.loads(joined), chunk.count
    except json.JSONDecodeError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Les fragments réassemblés ne forment pas du JSON valide : {e}",
        ) from e
