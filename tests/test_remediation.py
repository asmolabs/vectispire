"""Tests for remediation extraction out of scanner output.

Shapes below mirror real Grype JSON, in particular the distribution-advisory
case (`relatedVulnerabilities`) that container scans produce most of.
"""
from zanshin.services.remediation import extract_remediation


def test_extracts_fix_cvss_link_and_description_from_a_plain_match():
    match = {
        "vulnerability": {
            "id": "CVE-2024-0001",
            "severity": "Critical",
            "description": "Heap overflow in libfoo",
            "fix": {"versions": ["1.0.1", "1.1.0"], "state": "fixed"},
            "cvss": [
                {"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L", "metrics": {"baseScore": 9.8}}
            ],
            "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
        }
    }

    remediation = extract_remediation(match)

    assert remediation.fix_state == "fixed"
    assert remediation.fix_versions == "1.0.1, 1.1.0"
    assert remediation.cvss_score == 9.8
    assert remediation.cvss_vector == "CVSS:3.1/AV:N/AC:L"
    assert remediation.link.endswith("CVE-2024-0001")
    assert remediation.description == "Heap overflow in libfoo"


def test_falls_back_to_the_related_nvd_record_for_cvss_and_description():
    """A distro advisory (RHSA/DSA) carries the vendor severity and the fixed
    package version but no CVSS and no prose — those live on the linked NVD
    record. Reading only the primary record yields a null CVSS for exactly the
    findings container scans produce most of."""
    match = {
        "vulnerability": {
            "id": "RHSA-2024:1234",
            "severity": "High",
            "description": "",
            "fix": {"versions": ["7.76.1-29.el9_4.1"], "state": "fixed"},
            "cvss": [],
        },
        "relatedVulnerabilities": [
            {
                "id": "CVE-2024-7264",
                "description": "libcurl ASN.1 date parser read out of bounds",
                "cvss": [
                    {"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N", "metrics": {"baseScore": 6.5}}
                ],
                "dataSource": "https://nvd.nist.gov/vuln/detail/CVE-2024-7264",
            }
        ],
    }

    remediation = extract_remediation(match)

    assert remediation.cvss_score == 6.5
    assert remediation.cvss_vector.startswith("CVSS:3.1/")
    assert "out of bounds" in remediation.description
    # The fix stays the distribution's: that's the version an operator can
    # actually install.
    assert remediation.fix_versions == "7.76.1-29.el9_4.1"


def test_prefers_the_newest_cvss_generation():
    match = {
        "vulnerability": {
            "cvss": [
                {"version": "2.0", "vector": "AV:N/AC:L", "metrics": {"baseScore": 5.0}},
                {"version": "3.1", "vector": "CVSS:3.1/AV:N", "metrics": {"baseScore": 7.5}},
            ]
        }
    }

    remediation = extract_remediation(match)

    assert remediation.cvss_score == 7.5
    assert remediation.cvss_vector == "CVSS:3.1/AV:N"


def test_no_fix_available_is_reported_as_such():
    match = {"vulnerability": {"id": "CVE-1", "fix": {"versions": [], "state": "not-fixed"}}}

    remediation = extract_remediation(match)

    assert remediation.fix_state == "not-fixed"
    assert remediation.fix_versions is None


def test_versions_present_without_a_state_still_counts_as_fixed():
    match = {"vulnerability": {"id": "CVE-1", "fix": {"versions": ["2.0"]}}}

    assert extract_remediation(match).fix_state == "fixed"


def test_an_empty_match_yields_nothing_rather_than_raising():
    """Backends and versions differ in what they populate; missing data is
    normal, an exception mid-scan is not."""
    remediation = extract_remediation({})

    assert remediation.cvss_score is None
    assert remediation.fix_versions is None
    assert remediation.link is None
    assert remediation.description is None


def test_a_non_numeric_cvss_score_is_ignored_but_the_vector_is_kept():
    match = {
        "vulnerability": {
            "cvss": [{"version": "3.1", "vector": "CVSS:3.1/AV:N", "metrics": {"baseScore": "n/a"}}]
        }
    }

    remediation = extract_remediation(match)

    assert remediation.cvss_score is None
    assert remediation.cvss_vector == "CVSS:3.1/AV:N"


def test_reads_the_links_list_used_by_the_osv_translation():
    match = {"vulnerability": {"id": "CVE-1", "links": ["https://osv.dev/vulnerability/GHSA-x"]}}

    assert extract_remediation(match).link == "https://osv.dev/vulnerability/GHSA-x"


def test_overlong_values_are_truncated_to_their_column_width():
    match = {
        "vulnerability": {
            "dataSource": "https://example.com/" + "x" * 600,
            "cvss": [{"version": "3.1", "vector": "CVSS:3.1/" + "y" * 400, "metrics": {}}],
        }
    }

    remediation = extract_remediation(match)

    assert len(remediation.link) == 500
    assert len(remediation.cvss_vector) == 255
