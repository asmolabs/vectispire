import json
import logging
from typing import Dict, List

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

# Same severity vocabulary `_summarize_findings`/`_build_findings` already
# use for Grype/OSV findings — anything else the model produces (or
# omits) is normalized to "unknown" rather than left as free text, so
# `Finding.severity` stays consistent across every finding type.
VALID_SEVERITIES = {"critical", "high", "medium", "low", "negligible", "unknown"}

# Asks for a JSON array specifically (rather than free-form prose) so the
# response can be turned into normalized `Finding` rows — see
# `parse_findings()`. LLM output is never guaranteed to match this shape;
# `parse_findings` degrades to an empty list rather than raising when it
# doesn't, and the raw text is always preserved separately (see
# `ScanProcessor._run_ai_review`) so nothing is lost even when parsing fails.
SECURITY_ARCHITECT_PROMPT = (
    "As a security architect, review this code for security issues. "
    "Focus on concrete, actionable findings (e.g. injection risks, unsafe "
    "deserialization, missing authorization checks, hardcoded secrets, "
    "unsafe cryptography) rather than general style comments.\n\n"
    "Respond with ONLY a JSON array (no prose, no markdown code fence), "
    "one element per finding, each shaped exactly like this:\n"
    '{"severity": "critical|high|medium|low", "title": "short issue title", '
    '"file_path": "relative/path/if/known", "description": "what the issue is", '
    '"recommendation": "how to fix it"}\n'
    "If you find nothing, respond with an empty array: []"
)


class AiReviewService:
    """Optional, local LLM-based source code review via Ollama.

    This is a lightweight complement to the existing Grype/gitleaks/checkov
    scanners (see ADR-001) — a single prompt against whichever model is
    configured, not a structured SAST engine with its own analysis pipeline.
    Disabled by default (`ai_review_enabled`). Wired into `ScanProcessor` for
    repository scans (see its `_run_ai_review`): this service covers
    configuring *which* model to use, calling it (`review_code`), and
    normalizing its response into finding-shaped dicts (`parse_findings`) —
    turning those into actual `Finding` rows is `ScanProcessor`'s job, not
    this service's, so it stays free of any DB/ORM dependency.

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
        security-architect system prompt and returns its raw text response
        (expected to be a JSON array per the prompt — see `parse_findings`
        for turning it into structured data).

        Raises on failure rather than swallowing the error, unlike the
        read-only config methods above — a caller that actually wants a
        review result needs to know it didn't get one. `ScanProcessor`
        catches this and records it on the `AiReviewResult` row instead of
        letting it fail the scan.
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

    def parse_findings(self, response: str) -> List[Dict[str, str]]:
        """Best-effort parse of the model's response into a list of
        finding-shaped dicts (`severity`, `title`, `file_path`,
        `description`, `recommendation`).

        Never raises: LLM output is not guaranteed to be valid JSON, or to
        even be a JSON array — this returns an empty list rather than
        propagating a parsing error, so a malformed response degrades to
        "no structured findings" (the raw text is still preserved
        separately by the caller) instead of breaking the scan.
        """
        text = (response or "").strip()
        if not text:
            return []
        # Models occasionally wrap the array in a markdown code fence
        # despite being asked not to — strip it defensively.
        if text.startswith("```"):
            text = text.strip("`")
            if text[:4].lower() == "json":
                text = text[4:]
            text = text.strip()
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            logger.warning("AI review response was not valid JSON — no structured findings extracted")
            return []
        if not isinstance(data, list):
            return []

        findings = []
        for item in data:
            if not isinstance(item, dict):
                continue
            title = item.get("title") or item.get("issue") or item.get("summary")
            if not title:
                continue
            severity = str(item.get("severity", "unknown")).lower()
            if severity not in VALID_SEVERITIES:
                severity = "unknown"
            findings.append({
                "severity": severity,
                "title": str(title)[:255],
                "file_path": (str(item["file_path"]) if item.get("file_path") else None),
                "description": str(item.get("description", "")),
                "recommendation": str(item.get("recommendation", "")),
            })
        return findings
