import pytest

from zanshin.services.ai_review_service import (
    CODE_DELIMITER,
    AiReviewService,
    SETTING_KEY_AI_REVIEW_ENABLED,
    SETTING_KEY_AI_REVIEW_MODEL,
    SETTING_KEY_AI_REVIEW_OLLAMA_URL,
    DEFAULT_OLLAMA_URL,
    DEFAULT_AI_REVIEW_MODEL,
    DEFAULT_AI_REVIEW_DEPLOYMENT_MODE,
    FALLBACK_MODEL_SUGGESTIONS,
    SECURITY_ARCHITECT_PROMPT,
)


class FakeResponse:
    def __init__(self, payload, raise_error=None):
        self._payload = payload
        self._raise_error = raise_error

    def raise_for_status(self):
        if self._raise_error:
            raise self._raise_error

    def json(self):
        return self._payload


def test_is_enabled_defaults_to_false(settings_service):
    svc = AiReviewService(settings_service)
    assert svc.is_enabled() is False


def test_set_enabled_persists_and_is_reflected(settings_service):
    svc = AiReviewService(settings_service)
    svc.set_enabled(True)
    assert svc.is_enabled() is True
    svc.set_enabled(False)
    assert svc.is_enabled() is False


def test_ollama_url_defaults_and_can_be_set(settings_service):
    svc = AiReviewService(settings_service)
    assert svc.get_ollama_url() == DEFAULT_OLLAMA_URL

    # A hostname this machine cannot resolve is now refused rather than stored:
    # this endpoint receives source code, so "internal" has to be verifiable, and
    # a URL the server cannot resolve is one it could never reach anyway.
    svc.set_ollama_url("http://localhost:11434/")
    assert svc.get_ollama_url() == "http://localhost:11434/"


def test_set_ollama_url_rejects_empty(settings_service):
    svc = AiReviewService(settings_service)
    with pytest.raises(ValueError):
        svc.set_ollama_url("   ")


def test_selected_model_defaults_and_can_be_set(settings_service):
    svc = AiReviewService(settings_service)
    assert svc.get_selected_model() == DEFAULT_AI_REVIEW_MODEL

    svc.set_selected_model("gemma4:e4b-it-qat")
    assert svc.get_selected_model() == "gemma4:e4b-it-qat"


def test_set_selected_model_rejects_empty(settings_service):
    svc = AiReviewService(settings_service)
    with pytest.raises(ValueError):
        svc.set_selected_model("")
    with pytest.raises(ValueError):
        svc.set_selected_model("   ")


def test_set_selected_model_does_not_require_it_to_be_in_available_list(settings_service):
    """Deliberately permissive: Ollama may be unreachable, or the operator
    may be pre-configuring a model they haven't pulled yet."""
    svc = AiReviewService(settings_service, http_get=lambda *a, **k: FakeResponse({"models": []}))
    svc.set_selected_model("not-yet-pulled:latest")
    assert svc.get_selected_model() == "not-yet-pulled:latest"


def test_deployment_mode_defaults_to_local(settings_service):
    svc = AiReviewService(settings_service)
    assert svc.get_deployment_mode() == "local"
    assert DEFAULT_AI_REVIEW_DEPLOYMENT_MODE == "local"


def test_deployment_mode_can_be_set_to_docker(settings_service):
    svc = AiReviewService(settings_service)
    svc.set_deployment_mode("docker")
    assert svc.get_deployment_mode() == "docker"


def test_set_deployment_mode_rejects_unknown_values(settings_service):
    svc = AiReviewService(settings_service)
    with pytest.raises(ValueError):
        svc.set_deployment_mode("kubernetes")
    # rejecting an invalid value must not have silently persisted it
    assert svc.get_deployment_mode() == "local"


def test_list_available_models_reads_from_ollama_tags_endpoint(settings_service):
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        return FakeResponse({"models": [{"name": "gemma4:12b-it-qat"}, {"name": "llama3:8b"}]})

    svc = AiReviewService(settings_service, http_get=fake_get)
    models = svc.list_available_models()

    assert models == ["gemma4:12b-it-qat", "llama3:8b"]
    assert calls == [f"{DEFAULT_OLLAMA_URL}/api/tags"]


def test_list_available_models_respects_configured_url(settings_service):
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        return FakeResponse({"models": []})

    svc = AiReviewService(settings_service, http_get=fake_get)
    svc.set_ollama_url("http://localhost:11434")

    svc.list_available_models()

    assert calls == ["http://localhost:11434/api/tags"]


def test_list_available_models_falls_back_on_network_failure(settings_service):
    def broken_get(url, **kwargs):
        raise ConnectionError("simulated: ollama not running")

    svc = AiReviewService(settings_service, http_get=broken_get)

    assert svc.list_available_models() == FALLBACK_MODEL_SUGGESTIONS


def test_list_available_models_falls_back_when_tags_list_is_empty(settings_service):
    svc = AiReviewService(settings_service, http_get=lambda *a, **k: FakeResponse({"models": []}))

    assert svc.list_available_models() == FALLBACK_MODEL_SUGGESTIONS


def test_review_code_sends_security_architect_prompt_and_returns_content(settings_service):
    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["url"] = url
        captured["json"] = json
        return FakeResponse({"message": {"content": "No issues found."}})

    svc = AiReviewService(settings_service, http_post=fake_post)
    svc.set_selected_model("gemma4:12b-it-qat")

    result = svc.review_code("print('hello')")

    assert result == "No issues found."
    assert captured["url"] == f"{DEFAULT_OLLAMA_URL}/api/chat"
    assert captured["json"]["model"] == "gemma4:12b-it-qat"
    assert captured["json"]["messages"][0] == {"role": "system", "content": SECURITY_ARCHITECT_PROMPT}
    # The sample is delimited and labelled as data: it is the *scanned repository's*
    # source, i.e. attacker-controlled input to a model whose output reaches the UI.
    user_message = captured["json"]["messages"][1]
    assert user_message["role"] == "user"
    assert "print('hello')" in user_message["content"]
    assert user_message["content"].count(CODE_DELIMITER) == 2


def test_review_code_raises_on_failure_unlike_the_config_methods(settings_service):
    def broken_post(url, **kwargs):
        raise ConnectionError("simulated: ollama not running")

    svc = AiReviewService(settings_service, http_post=broken_post)

    with pytest.raises(ConnectionError):
        svc.review_code("print('hello')")


# --- parse_findings ---

def test_parse_findings_parses_a_well_formed_json_array(settings_service):
    svc = AiReviewService(settings_service)
    response = (
        '[{"severity": "high", "title": "Hardcoded secret", '
        '"file_path": "app.py", "description": "API key in source", '
        '"recommendation": "Use an env var"}]'
    )

    findings = svc.parse_findings(response)

    assert findings == [{
        "severity": "high",
        "title": "Hardcoded secret",
        "file_path": "app.py",
        "description": "API key in source",
        "recommendation": "Use an env var",
    }]


def test_parse_findings_strips_markdown_code_fence(settings_service):
    svc = AiReviewService(settings_service)
    response = '```json\n[{"severity": "low", "title": "Minor issue"}]\n```'

    findings = svc.parse_findings(response)

    assert findings == [{
        "severity": "low",
        "title": "Minor issue",
        "file_path": None,
        "description": "",
        "recommendation": "",
    }]


def test_parse_findings_normalizes_unrecognized_severity_to_unknown(settings_service):
    svc = AiReviewService(settings_service)
    response = '[{"severity": "super-duper-bad", "title": "Something"}]'

    findings = svc.parse_findings(response)

    assert findings[0]["severity"] == "unknown"


def test_parse_findings_skips_items_without_a_title(settings_service):
    svc = AiReviewService(settings_service)
    response = '[{"severity": "high"}, {"severity": "low", "title": "Real issue"}]'

    findings = svc.parse_findings(response)

    assert len(findings) == 1
    assert findings[0]["title"] == "Real issue"


def test_parse_findings_returns_empty_list_for_invalid_json(settings_service):
    svc = AiReviewService(settings_service)

    assert svc.parse_findings("this is not json at all") == []


def test_parse_findings_returns_empty_list_when_response_is_empty(settings_service):
    svc = AiReviewService(settings_service)

    assert svc.parse_findings("") == []
    assert svc.parse_findings(None) == []


def test_parse_findings_returns_empty_list_when_json_is_not_an_array(settings_service):
    svc = AiReviewService(settings_service)

    assert svc.parse_findings('{"severity": "high", "title": "Not a list"}') == []


def test_parse_findings_handles_empty_array(settings_service):
    svc = AiReviewService(settings_service)

    assert svc.parse_findings("[]") == []


def test_parse_findings_skips_non_dict_array_elements(settings_service):
    svc = AiReviewService(settings_service)
    response = '["just a string", {"severity": "high", "title": "Real issue"}]'

    findings = svc.parse_findings(response)

    assert len(findings) == 1
    assert findings[0]["title"] == "Real issue"
