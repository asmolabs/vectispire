import logging
from typing import List

import httpx

logger = logging.getLogger(__name__)

SETTING_KEY_AI_REVIEW_ENABLED = "ai_review_enabled"
SETTING_KEY_AI_REVIEW_MODEL = "ai_review_model"
SETTING_KEY_AI_REVIEW_OLLAMA_URL = "ai_review_ollama_url"

DEFAULT_OLLAMA_URL = "http://localhost:11434"
# Gemma 4 12B QAT (official Ollama library, 4-bit, ~7.2GB) is the documented
# default: no compatibility risk, "workstation-grade reasoning" tier per
# Google/Ollama's own positioning. `gemma4:e4b-it-qat` (~6.1GB) is a lighter
# alternative for CPU-only/low-RAM hosts, at some cost in review quality —
# see docs/architecture/ADR-001-scanner-backends.md.
DEFAULT_AI_REVIEW_MODEL = "gemma4:12b-it-qat"
# Shown only as a fallback suggestion when Ollama itself can't be reached
# (not running yet, wrong URL, ...) so the Settings page isn't empty during
# initial setup — never presented as "installed", see list_available_models.
FALLBACK_MODEL_SUGGESTIONS = ["gemma4:12b-it-qat", "gemma4:e4b-it-qat"]

SECURITY_ARCHITECT_PROMPT = (
    "As a security architect, could you review this code for security "
    "issues? Focus on concrete, actionable findings (e.g. injection risks, "
    "unsafe deserialization, missing authorization checks, hardcoded "
    "secrets, unsafe cryptography) rather than general style comments."
)


class AiReviewService:
    """Optional, local LLM-based source code review via Ollama.

    This is a lightweight complement to the existing Grype/gitleaks/checkov
    scanners (see ADR-001) — a single free-form prompt against whichever
    model is configured, not a structured SAST engine with its own finding
    taxonomy. Disabled by default (`ai_review_enabled`), and not yet wired
    into `ScanProcessor`/`Finding`/the scan-detail UI: this service only
    covers configuring *which* model to use and (via `review_code`)
    actually calling it — pipeline integration is a deliberate next step,
    not done here.

    The model choice is **not** a hardcoded list: `list_available_models()`
    reads live from Ollama's own `/api/tags` endpoint, so whatever the
    operator has actually pulled (`ollama pull ...`) is what shows up as
    selectable. If Ollama isn't reachable, a short list of documented
    suggestions is returned instead — never treated as "installed", just
    as something reasonable to type in.
    """

    def __init__(self, settings_service, http_get=httpx.get, http_post=httpx.post):
        self.settings_service = settings_service
        self._http_get = http_get
        self._http_post = http_post

    def is_enabled(self) -> bool:
        return self.settings_service.get_setting(SETTING_KEY_AI_REVIEW_ENABLED, "false") == "true"

    def set_enabled(self, enabled: bool) -> None:
        self.settings_service.update_setting(SETTING_KEY_AI_REVIEW_ENABLED, "true" if enabled else "false")

    def get_ollama_url(self) -> str:
        return self.settings_service.get_setting(SETTING_KEY_AI_REVIEW_OLLAMA_URL, DEFAULT_OLLAMA_URL)

    def set_ollama_url(self, url: str) -> None:
        if not url or not url.strip():
            raise ValueError("L'URL du service Ollama ne peut pas être vide.")
        self.settings_service.update_setting(SETTING_KEY_AI_REVIEW_OLLAMA_URL, url.strip())

    def get_selected_model(self) -> str:
        return self.settings_service.get_setting(SETTING_KEY_AI_REVIEW_MODEL, DEFAULT_AI_REVIEW_MODEL)

    def set_selected_model(self, model: str) -> None:
        """Persists the chosen model.

        Deliberately does *not* require the model to appear in
        `list_available_models()` first: Ollama may be temporarily
        unreachable, or an operator may want to pre-configure a model
        before pulling it. Only rejects an empty value.
        """
        if not model or not model.strip():
            raise ValueError("Le nom du modèle ne peut pas être vide.")
        self.settings_service.update_setting(SETTING_KEY_AI_REVIEW_MODEL, model.strip())

    def list_available_models(self) -> List[str]:
        """Queries Ollama's `/api/tags` for the models actually installed
        on the configured host. Falls back to `FALLBACK_MODEL_SUGGESTIONS`
        (never raises) if Ollama can't be reached — e.g. not running yet,
        wrong URL configured, network unavailable.
        """
        url = f"{self.get_ollama_url().rstrip('/')}/api/tags"
        try:
            response = self._http_get(url, timeout=5.0)
            response.raise_for_status()
            data = response.json()
            models = [m["name"] for m in data.get("models", []) if m.get("name")]
            return models or list(FALLBACK_MODEL_SUGGESTIONS)
        except Exception:
            logger.exception("Could not reach Ollama at %s to list installed models — falling back to suggestions", url)
            return list(FALLBACK_MODEL_SUGGESTIONS)

    def review_code(self, code: str, prompt: str = SECURITY_ARCHITECT_PROMPT) -> str:
        """Sends `code` to the configured Ollama model with a
        security-architect system prompt and returns its raw text response.

        Not called anywhere yet (no `ScanProcessor` integration): this is
        the building block a future scan-pipeline step or a manual/UI
        action would call. Raises on failure rather than swallowing the
        error, unlike the read-only methods above — a caller that actually
        wants a review result needs to know it didn't get one.
        """
        url = f"{self.get_ollama_url().rstrip('/')}/api/chat"
        payload = {
            "model": self.get_selected_model(),
            "messages": [
                {"role": "system", "content": prompt},
                {"role": "user", "content": code},
            ],
            "stream": False,
        }
        response = self._http_post(url, json=payload, timeout=120.0)
        response.raise_for_status()
        data = response.json()
        return data.get("message", {}).get("content", "")
