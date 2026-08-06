"""Tests for end-of-life detection.

The payload shapes below are endoflife.date's v1 API as it actually answers, checked
against the live endpoint while writing this: products carry `releases[]` with a cycle
`name`, an `eolFrom` date and `isEol`/`isMaintained` flags, and the purl identifier
index maps roughly 940 package URLs onto product names.

Two behaviours carry the feature and both are subtle enough to be worth pinning:
cycle matching (a string prefix would put Python 3.14 in the 3.1 cycle) and the
distribution path (a Syft SBOM has no purl for the operating system, which is the
single most valuable answer for a container image).
"""
import pytest

from zanshin.services.eol_service import EolService, _normalize_purl, _version_parts


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


def _release(name, eol_from=None, is_eol=False, is_maintained=True, latest=None):
    return {
        "name": name,
        "eolFrom": eol_from,
        "isEol": is_eol,
        "isMaintained": is_maintained,
        "latest": {"name": latest} if latest else None,
    }


PYTHON = {
    "name": "python",
    "releases": [
        _release("3.14", "2030-10-31", latest="3.14.7"),
        _release("3.9", "2025-10-31", is_eol=True, latest="3.9.23"),
        _release("3.1", "2012-04-09", is_eol=True, is_maintained=False),
    ],
}
RHEL = {
    "name": "rhel",
    "releases": [
        _release("9", "2032-05-31", latest="9.7"),
        _release("7", "2024-06-30", is_eol=True, latest="7.9"),
    ],
}

IDENTIFIERS = {
    "result": [
        {"identifier": "pkg:generic/python", "product": {"name": "python"}},
        {"identifier": "pkg:pypi/django", "product": {"name": "django"}},
    ]
}


@pytest.fixture()
def service(settings_service):
    """A service whose every HTTP call is answered from the tables above."""
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        if url.endswith("/identifiers/purl/"):
            return FakeResponse(IDENTIFIERS)
        for product in (PYTHON, RHEL):
            if url.endswith(f"/products/{product['name']}/"):
                return FakeResponse({"result": product})
        return FakeResponse(None, status_code=404)

    EolService.clear_cache()
    service = EolService(settings_service, http_get=fake_get)
    service.calls = calls
    yield service
    EolService.clear_cache()


# --- The distribution path ---

def test_an_end_of_life_distribution_is_flagged(service):
    """The highest-value check for a container image, and the one no package lookup
    would find: the base image's operating system is not a package in the SBOM."""
    findings = service.build_findings(1, {
        "distro": {"id": "rhel", "name": "Red Hat Enterprise Linux", "versionID": "7.9"},
        "artifacts": [],
    })

    assert len(findings) == 1
    assert findings[0].identifier == "EOL-rhel-7"
    assert findings[0].severity == "high"
    assert findings[0].package_version == "7.9"


def test_a_supported_distribution_is_not_flagged(service):
    """Everything reaches end of life eventually; flagging a release supported for
    another six years is noise that teaches people to filter the type out."""
    findings = service.build_findings(1, {
        "distro": {"id": "rhel", "versionID": "9.7"},
        "artifacts": [],
    })

    assert findings == []


def test_a_pretty_version_string_still_resolves(service):
    """Syft reports `version: "9.7 (Plow)"` alongside `versionID`; a parser that
    choked on the codename would silently stop checking distributions."""
    assert _version_parts("9.7 (Plow)") == ["9", "7"]
    assert _version_parts("3.12.1-rc1") == ["3", "12", "1"]


def test_an_unknown_distribution_is_not_an_error(service):
    findings = service.build_findings(1, {
        "distro": {"id": "notadistro", "versionID": "1.0"}, "artifacts": [],
    })

    assert findings == []


# --- The package path ---

def test_a_package_is_matched_by_purl(service):
    """One request returns the whole identifier index, so there is no mapping table to
    maintain and none to rot."""
    findings = service.build_findings(1, {
        "artifacts": [
            {"name": "python", "version": "3.9.18", "purl": "pkg:generic/python@3.9.18"},
        ],
    })

    assert len(findings) == 1
    assert findings[0].identifier == "EOL-python-3.9"


def test_the_purl_version_and_qualifiers_are_ignored_when_matching(service):
    """An SBOM purl carries both; the catalogue's identifiers carry neither."""
    assert _normalize_purl("pkg:rpm/redhat/openssl@3.5.1-7.el9?arch=x86_64") == "pkg:rpm/redhat/openssl"
    assert _normalize_purl("pkg:generic/python@3.9.18") == "pkg:generic/python"


def test_a_package_the_catalogue_does_not_track_is_skipped(service):
    """Coverage is deliberately partial: end of life is a property of platforms, and
    an individual library's risk is what the vulnerability scanners answer."""
    findings = service.build_findings(1, {
        "artifacts": [
            {"name": "libfoo", "version": "1.0", "purl": "pkg:rpm/redhat/libfoo@1.0"},
        ],
    })

    assert findings == []


def test_an_artifact_without_a_version_is_skipped(service):
    findings = service.build_findings(1, {
        "artifacts": [{"name": "python", "purl": "pkg:generic/python"}],
    })

    assert findings == []


# --- Cycle matching ---

def test_the_cycle_is_matched_component_wise_not_as_a_string(service):
    """"3.14" starts with "3.1" as a string, so a prefix match would place Python 3.14
    in the 3.1 cycle — end of life 2012 — and report a supported runtime as dead."""
    release = service._match_release(PYTHON, "3.14.7")

    assert release["name"] == "3.14"


def test_the_longest_matching_cycle_wins(service):
    product = {"releases": [_release("8"), _release("8.1", "2020-01-01", is_eol=True)]}

    assert service._match_release(product, "8.1.2")["name"] == "8.1"
    assert service._match_release(product, "8.0.1")["name"] == "8"


def test_a_version_outside_every_cycle_matches_nothing(service):
    assert service._match_release(PYTHON, "2.7.18") is None


# --- Severity and remediation ---

def test_an_upcoming_end_of_life_is_a_warning_not_an_incident(service, setting_repository):
    from datetime import date, timedelta

    from zanshin.models.setting import Setting

    soon = (date.today() + timedelta(days=30)).isoformat()
    product = {"name": "python", "releases": [_release("3.9", soon, latest="3.9.23")]}

    def fake_get(url, **kwargs):
        if url.endswith("/identifiers/purl/"):
            return FakeResponse({"result": []})
        return FakeResponse({"result": product})

    setting_repository.save(Setting(key="eol_warn_days", value="90"))
    EolService.clear_cache()
    service = EolService(service.settings_service, http_get=fake_get)

    findings = service.build_findings(1, {"distro": {"id": "python", "versionID": "3.9"}})

    assert findings[0].severity == "medium"
    EolService.clear_cache()


def test_a_release_beyond_the_warning_window_is_silent(service):
    findings = service.build_findings(1, {"distro": {"id": "rhel", "versionID": "9.0"}})

    assert findings == []


def test_a_discontinued_release_without_a_date_is_flagged(service):
    findings = service.build_findings(1, {
        "artifacts": [{"name": "python", "version": "3.1.5", "purl": "pkg:generic/python@3.1.5"}],
    })

    assert findings[0].severity == "high"


def test_the_recommended_version_is_the_newest_maintained_one(service):
    """Put on `fix_versions` so an end-of-life finding reads like every other
    actionable one — in the UI, the exports and the SARIF message."""
    findings = service.build_findings(1, {"distro": {"id": "rhel", "versionID": "7.9"}})

    assert findings[0].fix_versions == "9.7"
    assert findings[0].fix_state == "fixed"


def test_the_finding_identifies_the_cycle_not_the_patch_version(service):
    """The fingerprint is built from the identifier, so an issue has to keep its
    history and its triage as the patch version moves within a cycle."""
    first = service.build_findings(1, {
        "artifacts": [{"name": "python", "version": "3.9.1", "purl": "pkg:generic/python@3.9.1"}],
    })
    second = service.build_findings(2, {
        "artifacts": [{"name": "python", "version": "3.9.18", "purl": "pkg:generic/python@3.9.18"}],
    })

    assert first[0].identifier == second[0].identifier


def test_the_same_product_is_reported_once(service):
    """A container image lists the same runtime under several packages; one finding per
    cycle is what a human can act on."""
    findings = service.build_findings(1, {
        "distro": {"id": "python", "versionID": "3.9"},
        "artifacts": [
            {"name": "python", "version": "3.9.1", "purl": "pkg:generic/python@3.9.1"},
        ],
    })

    assert len(findings) == 1


# --- Failure modes ---

def test_the_service_can_be_turned_off(service, setting_repository):
    from zanshin.models.setting import Setting

    setting_repository.save(Setting(key="eol_detection_enabled", value="false"))

    assert service.build_findings(1, {"distro": {"id": "rhel", "versionID": "7.9"}}) == []


def test_a_network_failure_yields_no_findings_rather_than_an_exception(settings_service):
    """Same contract as enrichment: a scan with valid results must never fail because
    an optional lookup did not answer."""
    def broken_get(url, **kwargs):
        raise ConnectionError("simulated: endoflife.date unreachable")

    EolService.clear_cache()
    service = EolService(settings_service, http_get=broken_get)

    assert service.build_findings(1, {"distro": {"id": "rhel", "versionID": "7.9"}}) == []
    EolService.clear_cache()


def test_a_missing_sbom_yields_no_findings(service):
    assert service.build_findings(1, None) == []
    assert service.build_findings(1, {}) == []


def test_the_catalogue_is_fetched_once_per_process(service):
    """The identifier index is one document and the container rebuilds this service
    per request, which is why the cache is on the class."""
    sbom = {"artifacts": [{"name": "python", "version": "3.9.1", "purl": "pkg:generic/python@3.9.1"}]}
    service.build_findings(1, sbom)
    service.build_findings(2, sbom)

    assert service.calls.count("https://endoflife.date/api/v1/identifiers/purl/") == 1
