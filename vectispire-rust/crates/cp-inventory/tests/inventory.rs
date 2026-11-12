use vectispire_cp_inventory::*;
use vectispire_protocol::{ApiContract, ApiEndpoint, ApiVisibility};

#[test]
fn test_license_risk_classification() {
    assert_eq!(LicenseRiskCategory::classify("MIT"), LicenseRiskCategory::Permissive);
    assert_eq!(LicenseRiskCategory::classify("Apache-2.0"), LicenseRiskCategory::Permissive);
    assert_eq!(LicenseRiskCategory::classify("BSD-3-Clause"), LicenseRiskCategory::Permissive);
    assert_eq!(LicenseRiskCategory::classify("LGPL-3.0-only"), LicenseRiskCategory::WeakCopyleft);
    assert_eq!(LicenseRiskCategory::classify("MPL-2.0"), LicenseRiskCategory::WeakCopyleft);
    assert_eq!(LicenseRiskCategory::classify("GPL-3.0-only"), LicenseRiskCategory::StrongCopyleft);
    assert_eq!(LicenseRiskCategory::classify("AGPL-3.0-only"), LicenseRiskCategory::StrongCopyleft);
    assert_eq!(LicenseRiskCategory::classify("Commercial"), LicenseRiskCategory::Forbidden);
    assert_eq!(LicenseRiskCategory::classify("Unknown-Custom"), LicenseRiskCategory::Unknown);
    assert_eq!(LicenseRiskCategory::classify(""), LicenseRiskCategory::Unknown);
}

#[test]
fn test_license_policy_compliance() {
    let mut policy = LicensePolicy::default();
    assert!(policy.is_compliant(Some("MIT"), LicenseRiskCategory::Permissive));
    assert!(!policy.is_compliant(Some("GPL-3.0-only"), LicenseRiskCategory::StrongCopyleft));

    // Allow GPL via explicitly_allowed_licenses (uppercase normalized)
    policy.explicitly_allowed_licenses.insert("GPL-3.0-ONLY".to_owned());
    assert!(policy.is_compliant(Some("GPL-3.0-only"), LicenseRiskCategory::StrongCopyleft));

    // Deny MIT explicitly
    policy.explicitly_disallowed_licenses.insert("MIT".to_owned());
    assert!(!policy.is_compliant(Some("MIT"), LicenseRiskCategory::Permissive));
}

#[test]
fn test_blast_radius_score_calculation() {
    let zero = BlastRadiusReport::calculate_score(0, 0, 0, 0, 0.0);
    assert_eq!(zero, 0);

    let score1 = BlastRadiusReport::calculate_score(1, 1, 0, 1, 7.5);
    assert!(score1 > 0 && score1 <= 100);

    let max_score = BlastRadiusReport::calculate_score(100, 50, 50, 20, 10.0);
    assert_eq!(max_score, 100);
}

#[test]
fn test_ecosystem_extraction() {
    assert_eq!(extract_ecosystem(Some("pkg:maven/org.apache/commons-io@2.11.0")), "Maven");
    assert_eq!(extract_ecosystem(Some("pkg:npm/lodash@4.17.21")), "npm");
    assert_eq!(extract_ecosystem(Some("pkg:pypi/requests@2.28.0")), "PyPI");
    assert_eq!(extract_ecosystem(Some("pkg:golang/github.com/gin-gonic/gin@1.8.0")), "Go");
    assert_eq!(extract_ecosystem(Some("pkg:apk/alpine-baselayout@3.2.0")), "Alpine");
    assert_eq!(extract_ecosystem(Some("pkg:deb/debian/tar@1.34")), "Debian");
    assert_eq!(extract_ecosystem(Some("pkg:oci/ubuntu@sha256:123")), "OCI");
    assert_eq!(extract_ecosystem(None), "Generic");
    assert_eq!(extract_ecosystem(Some("unknown")), "Generic");
}

#[test]
fn test_sensitive_path_detection() {
    assert!(is_sensitive_path("/admin/users"));
    assert!(is_sensitive_path("/actuator/health"));
    assert!(is_sensitive_path("/debug/pprof"));
    assert!(is_sensitive_path("/metrics"));
    assert!(is_sensitive_path("/env/properties"));
    assert!(is_sensitive_path("/internal/routes"));
    assert!(!is_sensitive_path("/api/v1/catalog/items"));
    assert!(!is_sensitive_path("/home"));
}

#[test]
fn test_attack_surface_summary() {
    let endpoints = vec![
        ApiEndpoint {
            method: Some("GET".to_owned()),
            path: "/api/public".to_owned(),
            auth_required: false,
            auth_type: None,
            visibility: ApiVisibility::Public,
            file_path: None,
            line_number: None,
            framework: None,
            operation_id: None,
            summary: None,
            tags: None,
        },
        ApiEndpoint {
            method: Some("POST".to_owned()),
            path: "/admin/secrets".to_owned(),
            auth_required: false,
            auth_type: None,
            visibility: ApiVisibility::Internal,
            file_path: None,
            line_number: None,
            framework: None,
            operation_id: None,
            summary: None,
            tags: None,
        },
    ];

    let summary = AttackSurfaceSummary::from(&endpoints, None);
    assert_eq!(summary.total_endpoints, 2);
    assert_eq!(summary.public_endpoints, 1);
    assert_eq!(summary.internal_endpoints, 1);
    assert_eq!(summary.unauthenticated_endpoints, 2);
    assert_eq!(summary.sensitive_unprotected_endpoints, 1);
    assert_eq!(summary.shadow_endpoints, 0);
}

#[test]
fn test_shadow_api_diff_computation() {
    let contracts = vec![ApiContract {
        contract_path: Some("openapi.yaml".to_owned()),
        format: Some("openapi".to_owned()),
        title: Some("Service API".to_owned()),
        version: Some("1.0.0".to_owned()),
        endpoints_count: 1,
        declared_paths: vec![Some("/api/items".to_owned()), Some("/api/users".to_owned())],
    }];

    let scanned_endpoints = vec![
        ApiEndpoint {
            method: Some("GET".to_owned()),
            path: "/api/items".to_owned(),
            auth_required: true,
            auth_type: None,
            visibility: ApiVisibility::Public,
            file_path: None,
            line_number: None,
            framework: None,
            operation_id: None,
            summary: None,
            tags: None,
        },
        ApiEndpoint {
            method: Some("DELETE".to_owned()),
            path: "/api/unlisted_internal".to_owned(),
            auth_required: false,
            auth_type: None,
            visibility: ApiVisibility::Public,
            file_path: None,
            line_number: None,
            framework: None,
            operation_id: None,
            summary: None,
            tags: None,
        },
    ];

    let diff = ShadowApiDiff::compute(&scanned_endpoints, &contracts);
    assert_eq!(diff.documented_endpoints.len(), 1);
    assert_eq!(diff.documented_endpoints[0].path, "/api/items");
    assert_eq!(diff.shadow_endpoints.len(), 1);
    assert_eq!(diff.shadow_endpoints[0].path, "/api/unlisted_internal");
    assert_eq!(diff.zombie_endpoints.len(), 1);
    assert_eq!(diff.zombie_endpoints[0], "/api/users");
}
