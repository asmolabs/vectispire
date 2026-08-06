"""The agent's side of the HTTP protocol.

One class, four calls, no policy: `worker.py` decides what to do, this decides how
to say it. Errors are raised as `ControllerError` with the controller's own message
attached, because the messages the API returns are written to be read by whoever is
setting an agent up.
"""
import json
import logging
import uuid
from typing import Any, Dict, List, Optional

import httpx

from zanshin.scan_contract import CONTRACT_VERSION, ScanArtifacts, ScanTask

logger = logging.getLogger(__name__)

# A claim request deliberately waits (long-poll), so its timeout has to exceed the
# controller's own wait or the agent would abandon every poll of an idle queue.
CLAIM_TIMEOUT_MARGIN_SECONDS = 15
DEFAULT_TIMEOUT_SECONDS = 60.0


class ControllerError(RuntimeError):
    """The controller refused or could not serve a request."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class LeaseLost(ControllerError):
    """This agent no longer holds the job it was reporting on.

    Its own class because it is the one error the worker must not treat as a
    failure: nothing is wrong with the agent, the work was simply reassigned, and
    the right response is to drop it and ask for the next job.
    """


class AgentClient:
    def __init__(self, config, http_client: Optional[httpx.Client] = None):
        self.config = config
        # A persistent client here, unlike the one-off `httpx.post` calls elsewhere
        # in the codebase: this process makes a request every few seconds for its
        # whole life, so connection reuse is the whole point rather than a
        # micro-optimisation. Injectable for tests.
        self._client = http_client or httpx.Client(
            base_url=config.url,
            headers={"Authorization": f"Bearer {config.token}"},
            timeout=DEFAULT_TIMEOUT_SECONDS,
            verify=config.verify_tls,
        )

    def close(self) -> None:
        self._client.close()

    # --- Calls ------------------------------------------------------------

    def hello(self, report: Dict[str, Any]) -> Dict[str, Any]:
        report = {**report, "contract_version": CONTRACT_VERSION}
        response = self._client.post("/api/v1/agents/hello", json=report)
        self._raise_for_status(response)
        return response.json()

    def claim(self, wait_seconds: int) -> Optional[ScanTask]:
        """Ask for one job, waiting up to `wait_seconds`. `None` if there is none."""
        response = self._client.get(
            "/api/v1/agents/jobs",
            params={"wait": wait_seconds},
            timeout=wait_seconds + CLAIM_TIMEOUT_MARGIN_SECONDS,
        )
        if response.status_code == 204:
            return None
        self._raise_for_status(response)
        return ScanTask.model_validate(response.json())

    def heartbeat(self, scan_id: int, message: Optional[str] = None) -> None:
        response = self._client.post(
            f"/api/v1/agents/jobs/{scan_id}/heartbeat", json={"message": message}
        )
        if response.status_code == 409:
            raise LeaseLost(self._detail(response), response.status_code)
        self._raise_for_status(response)

    def report_success(
        self, scan_id: int, artifacts: ScanArtifacts, message_id: str, chunk_bytes: int
    ) -> Dict[str, Any]:
        """Post artifacts, in one request or in slices if they are large.

        `message_id` is generated once per report by the caller and reused for every
        retry of that same report — that is what makes a retry harmless on the
        controller's side.
        """
        payload = artifacts.model_dump_json()
        if len(payload) <= chunk_bytes:
            return self._post_result(scan_id, {
                "message_id": message_id,
                "status": "succeeded",
                "artifacts": json.loads(payload),
            })

        upload_id = str(uuid.uuid4())
        slices = _slice(payload, chunk_bytes)
        logger.info(
            "Result for scan %s is %d bytes; sending it in %d slices",
            scan_id, len(payload), len(slices),
        )
        acknowledgement: Dict[str, Any] = {}
        for index, data in enumerate(slices):
            acknowledgement = self._post_result(scan_id, {
                "message_id": message_id,
                "status": "succeeded",
                "chunk": {
                    "upload_id": upload_id,
                    "index": index,
                    "count": len(slices),
                    "data": data,
                },
            })
        return acknowledgement

    def report_failure(self, scan_id: int, error: str, message_id: str) -> Dict[str, Any]:
        return self._post_result(scan_id, {
            "message_id": message_id,
            "status": "failed",
            "error": error[:2000],
        })

    # --- Internals --------------------------------------------------------

    def _post_result(self, scan_id: int, body: Dict[str, Any]) -> Dict[str, Any]:
        response = self._client.post(f"/api/v1/agents/jobs/{scan_id}/result", json=body)
        if response.status_code in (403, 404):
            # The job is no longer ours (reassigned, cancelled, or the scan is gone).
            # Distinct from a transport failure: retrying would be pointless.
            raise LeaseLost(self._detail(response), response.status_code)
        self._raise_for_status(response)
        return response.json()

    def _raise_for_status(self, response: httpx.Response) -> None:
        if response.is_success:
            return
        raise ControllerError(self._detail(response), response.status_code)

    @staticmethod
    def _detail(response: httpx.Response) -> str:
        """The controller's own message, which is written to be read by an operator
        setting an agent up — so it is worth surfacing verbatim rather than
        replacing with "HTTP 403"."""
        try:
            payload = response.json()
        except Exception:
            return f"HTTP {response.status_code}: {response.text[:500]}"
        detail = payload.get("detail") if isinstance(payload, dict) else None
        return f"HTTP {response.status_code}: {detail or response.text[:500]}"


def _slice(payload: str, size: int) -> List[str]:
    return [payload[i:i + size] for i in range(0, len(payload), size)]
