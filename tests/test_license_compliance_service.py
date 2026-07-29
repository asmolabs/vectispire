from zanshin.services.license_compliance_service import (
    LicenseComplianceService,
    SETTING_KEY_LICENSE_BLOCKLIST,
)

SAMPLE_SBOM = {
    "artifacts": [
        {"name": "gpl-lib", "version": "1.0", "purl": "pkg:pypi/gpl-lib@1.0", "licenses": ["GPL-3.0-only"]},
        {"name": "mit-lib", "version": "2.0", "purl": "pkg:pypi/mit-lib@2.0", "licenses": [{"value": "MIT", "spdxExpression": "MIT"}]},
        {"name": "agpl-lib", "version": "3.0", "purl": "pkg:pypi/agpl-lib@3.0", "licenses": [{"spdxExpression": "AGPL-3.0-only"}]},
        {"name": "no-license-lib", "version": "4.0", "licenses": []},
    ]
}


def test_empty_blocklist_flags_nothing(settings_service):
    svc = LicenseComplianceService(settings_service)
    assert svc.build_findings(1, SAMPLE_SBOM) == []


def test_blocklist_matches_string_and_dict_license_formats_case_insensitively(settings_service):
    settings_service.update_setting(SETTING_KEY_LICENSE_BLOCKLIST, "gpl-3.0-only, AGPL-3.0-ONLY")
    svc = LicenseComplianceService(settings_service)

    findings = svc.build_findings(1, SAMPLE_SBOM)

    assert {f.package_name for f in findings} == {"gpl-lib", "agpl-lib"}
    assert all(f.type == "license" and f.source == "syft" and f.scan_id == 1 for f in findings)


def test_blocklist_with_no_matching_license_flags_nothing(settings_service):
    settings_service.update_setting(SETTING_KEY_LICENSE_BLOCKLIST, "BSD-3-CLAUSE")
    svc = LicenseComplianceService(settings_service)

    assert svc.build_findings(1, SAMPLE_SBOM) == []


def test_get_blocklist_parses_and_normalizes(settings_service):
    settings_service.update_setting(SETTING_KEY_LICENSE_BLOCKLIST, " gpl-3.0-only ,, AGPL-3.0-only")
    svc = LicenseComplianceService(settings_service)

    assert svc.get_blocklist() == {"GPL-3.0-ONLY", "AGPL-3.0-ONLY"}
