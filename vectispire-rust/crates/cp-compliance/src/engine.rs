//! The pure evaluation of regulatory compliance from security state — Java's `ComplianceEngine` and
//! `ComplianceEvaluation`.
//!
//! Every sentence, ceiling and threshold is Java's, held to `reference/compliance/engine.json`. **Java's `int`
//! arithmetic is reproduced, overflow included**: the engine casts each issue count to `int` before multiplying it
//! (`(int) input.criticalIssues() * 20`), so a count past two billion wraps there, and the wrapping operations below
//! answer what Java answers rather than panicking where it does not.

use serde::Serialize;

use crate::framework::{Category, ComplianceControl, ComplianceFramework, Status};
use vectispire_domain::java_math::round_f32;

/// Aggregated security posture input for compliance assessment — `ComplianceEngine.PostureInput`.
///
/// `scanned_targets` are the targets observed at all, ever; `freshly_scanned_targets` those observed inside
/// `freshness_window_days`, the operator's number: ever-scanned is a memory, not a control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostureInput {
    pub total_targets: i32,
    pub scanned_targets: i32,
    pub freshly_scanned_targets: i32,
    pub freshness_window_days: i32,
    pub gate_passing_targets: i32,
    pub critical_issues: i64,
    pub high_issues: i64,
    pub medium_issues: i64,
    pub low_issues: i64,
    pub kev_issues: i64,
    pub overdue_issues: i64,
    pub secret_issues: i64,
    pub sast_issues: i64,
    pub iac_issues: i64,
    pub targets_with_sbom: i32,
    pub audit_chain_valid: bool,
}

/// What the control plane has switched on, as opposed to what it found in the fleet — `PlatformPosture`.
///
/// A second input and not more fields of [`PostureInput`]: those measure somebody else's code, these are properties
/// of this deployment, and an assessor treats a control differently from a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformPosture {
    pub encryption_configured: bool,
    pub external_kms: bool,
    pub audit_mirror_configured: bool,
    pub four_eyes_required: bool,
    pub single_sign_on_configured: bool,
    pub password_login_open: bool,
    pub password_accounts: PasswordAccounts,
}

impl PlatformPosture {
    /// Everything on — `FULLY_ENABLED`.
    pub const FULLY_ENABLED: PlatformPosture = PlatformPosture {
        encryption_configured: true,
        external_kms: true,
        audit_mirror_configured: true,
        four_eyes_required: true,
        single_sign_on_configured: true,
        password_login_open: false,
        password_accounts: PasswordAccounts { accounts: 0, without_second_factor: 0 },
    };
}

/// The active accounts holding a local password, and those of them with no TOTP second factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordAccounts {
    pub accounts: i64,
    pub without_second_factor: i64,
}

/// One framework's result — `ComplianceEvaluation`. `score_percentage` is zero wherever the status is
/// [`Status::NoData`]: no measurement, not a measured zero — read the status first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ComplianceEvaluation {
    pub framework: ComplianceFramework,
    pub score_percentage: i32,
    pub overall_status: Status,
    pub controls: Vec<ControlAssessment>,
}

/// One control's result — `ComplianceEvaluation.ControlAssessment`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlAssessment {
    pub control: &'static ComplianceControl,
    pub status: Status,
    pub score_percentage: i32,
    pub details: String,
    pub remediation_guidance: String,
}

/// Every framework, in their declaration order — `evaluateAll`.
pub fn evaluate_all(input: &PostureInput, platform: &PlatformPosture) -> Vec<ComplianceEvaluation> {
    ComplianceFramework::ALL.into_iter().map(|framework| evaluate(framework, input, platform)).collect()
}

/// One framework — `evaluate`.
pub fn evaluate(
    framework: ComplianceFramework,
    input: &PostureInput,
    platform: &PlatformPosture,
) -> ComplianceEvaluation {
    let assessments: Vec<ControlAssessment> = framework
        .controls()
        .iter()
        .map(|control| capped_by_platform(evaluate_control(control, input), platform))
        .collect();

    // A control with no data makes the framework's verdict no data too, even beside a measured one: the only
    // control measured on an unobserved estate is the audit trail's, and a framework scored on it alone would present
    // the platform's sign-in policy as the estate's posture. The controls keep their own statuses.
    if assessments.iter().any(|assessment| !assessment.status.measured()) {
        return ComplianceEvaluation {
            framework,
            score_percentage: 0,
            overall_status: Status::NoData,
            controls: assessments,
        };
    }

    let total_score = assessments.iter().fold(0i32, |sum, assessment| sum.wrapping_add(assessment.score_percentage));
    let non_compliant = assessments.iter().any(|assessment| assessment.status == Status::NonCompliant);
    let partial = assessments.iter().any(|assessment| assessment.status == Status::Partial);

    // `Math.round((float) totalScore / assessments.size())` — in `float`, as Java divides.
    let overall_score =
        if assessments.is_empty() { 100 } else { round_f32(total_score as f32 / assessments.len() as f32) };
    let overall_status = if non_compliant || overall_score < 70 {
        Status::NonCompliant
    } else if partial || overall_score < 95 {
        Status::Partial
    } else {
        Status::Compliant
    };
    ComplianceEvaluation { framework, score_percentage: overall_score, overall_status, controls: assessments }
}

fn evaluate_control(control: &'static ComplianceControl, input: &PostureInput) -> ControlAssessment {
    if control.category != Category::AuditAndLogging && input.scanned_targets == 0 {
        return no_data(control, input);
    }
    match control.category {
        Category::VulnerabilityManagement => evaluate_vulnerabilities(control, input),
        Category::SupplyChain => evaluate_supply_chain(control, input),
        Category::SecretsManagement => evaluate_secrets(control, input),
        Category::SecureCoding => evaluate_secure_coding(control, input),
        Category::InfrastructureAsCode => evaluate_iac(control, input),
        Category::Governance => evaluate_governance(control, input),
        Category::AuditAndLogging => evaluate_audit(control, input),
    }
}

/// A control of the estate with no target ever observed: not measured, whatever the counts say. Only when nothing
/// was observed — an estate observed in part keeps the coverage cap.
fn no_data(control: &'static ComplianceControl, input: &PostureInput) -> ControlAssessment {
    let details = if input.total_targets == 0 {
        "No target is registered: nothing here measures this control yet.".to_owned()
    } else {
        format!(
            "None of the {} target(s) has ever been scanned successfully: nothing here measures this control yet.",
            input.total_targets
        )
    };
    ControlAssessment {
        control,
        status: Status::NoData,
        score_percentage: 0,
        details,
        remediation_guidance:
            "Register and scan the estate: a control cannot be evidenced before anything has been observed.".to_owned(),
    }
}

/// Lowers an assessment when the platform capability the control rests on is switched off — a cap, not a penalty:
/// a control cannot read compliant on evidence that does not cover it.
fn capped_by_platform(assessment: ControlAssessment, platform: &PlatformPosture) -> ControlAssessment {
    match assessment.control.category {
        Category::SecretsManagement => {
            if platform.encryption_configured {
                assessment
            } else {
                capped(
                    assessment,
                    60,
                    "No encryption key is configured, so secrets stored by Vectispire itself (deployment SSH keys, \
                     integration tokens) cannot be encrypted at rest — this control counts only what was found in \
                     the scanned repositories",
                    "Set ENCRYPTION_KEY (or ENCRYPTION_KEY_FILE) and re-save the stored credentials.",
                )
            }
        }
        // Two ceilings: what the chain cannot prove of itself (a deletion), then what it does not prove either (the
        // name on an entry).
        Category::AuditAndLogging => {
            let mirrored = if platform.audit_mirror_configured {
                assessment
            } else {
                capped(
                    assessment,
                    70,
                    "No audit mirror is configured. The hash chain makes a modified entry detectable, but it cannot \
                     detect the deletion of an entry nobody descends from — the last one written, which is the one an \
                     attacker removes",
                    "Configure vectispire.audit.mirror-path and ship the file off the host, so the deletion has to be \
                     performed twice in two media.",
                )
            };
            authentication_cap(mirrored, platform)
        }
        Category::Governance => {
            if platform.four_eyes_required {
                assessment
            } else {
                capped(
                    assessment,
                    75,
                    "Four-eyes approval is disabled, so the account that raises an exemption can also grant it — the \
                     gate verdict below is advisory rather than enforced",
                    "Enable triage_four_eyes_required so a dismissal needs a second person.",
                )
            }
        }
        _ => assessment,
    }
}

/// The ceiling identity puts on accountability — `authenticationCap`. A local TOTP on every password account counts
/// (85, each account chooses it); a provider beside an open password takes the same ceiling; both doors as the
/// control describes are left alone.
fn authentication_cap(assessment: ControlAssessment, platform: &PlatformPosture) -> ControlAssessment {
    if !platform.single_sign_on_configured {
        let local = platform.password_accounts;
        if local.accounts > 0 && local.without_second_factor == 0 {
            return capped_owned(
                assessment,
                85,
                &format!(
                    "No identity provider is configured. Every one of the {} active account(s) holding a local \
                     password has enrolled a TOTP second factor, but each account chooses it: nothing here requires \
                     it of the next account, or keeps one from switching it off",
                    local.accounts
                ),
                "Set VECTISPIRE_OIDC_ISSUER so the organisation's own authentication policy — including its second \
                 factor — stands behind every entry in this log.",
            );
        }
        return capped_owned(
            assessment,
            65,
            &format!(
                "No identity provider is configured, and {} of the {} active account(s) holding a local password have \
                 no second factor. The audit chain proves an entry was not altered; it cannot prove the name on it \
                 belongs to the person who acted",
                local.without_second_factor, local.accounts
            ),
            "Set VECTISPIRE_OIDC_ISSUER so the organisation's own authentication policy — including its second factor \
             — stands behind every entry in this log, or have every account enrol a TOTP second factor under Account.",
        );
    }
    if platform.password_login_open {
        return capped(
            assessment,
            85,
            "An identity provider is configured, and local password sign-in is still open beside it. Whatever second \
             factor the realm enforces can be walked around through the other door",
            "Set VECTISPIRE_PASSWORD_LOGIN=false once single sign-on is verified working. It is refused, loudly, while \
             no provider is configured.",
        );
    }
    assessment
}

fn capped(assessment: ControlAssessment, ceiling: i32, why: &'static str, how: &'static str) -> ControlAssessment {
    capped_owned(assessment, ceiling, why, how)
}

/// Keeps the lower of the two scores, and never reports better than partial. A control with no data keeps it — a
/// cap stops a green tick, and there is none to stop; the note still says which switch is off.
fn capped_owned(assessment: ControlAssessment, ceiling: i32, why: &str, how: &str) -> ControlAssessment {
    let status = match assessment.status {
        Status::NonCompliant | Status::NoData => assessment.status,
        Status::Compliant | Status::Partial => Status::Partial,
    };
    let remediation_guidance = if why.is_empty() {
        assessment.remediation_guidance
    } else {
        format!("{how} {}", assessment.remediation_guidance)
    };
    ControlAssessment {
        control: assessment.control,
        status,
        score_percentage: assessment.score_percentage.min(ceiling),
        details: format!("{} {why}.", assessment.details),
        remediation_guidance,
    }
}

/// Java's `(int)` of a `long`: the low 32 bits, as the engine casts each count before it multiplies it.
#[allow(clippy::cast_possible_truncation)] // The truncation is the point: it is Java's.
fn int(value: i64) -> i32 {
    value as i32
}

fn evaluate_vulnerabilities(control: &'static ComplianceControl, input: &PostureInput) -> ControlAssessment {
    let mut score: i32 = 100;
    let mut notes = Vec::new();
    let mut guidance = Vec::new();

    if input.critical_issues > 0 {
        score = score.wrapping_sub(50.min(int(input.critical_issues).wrapping_mul(20)));
        notes.push(format!("{} critical CVE(s) detected", input.critical_issues));
        guidance.push("Remediate or triage all critical CVEs immediately.");
    }
    if input.kev_issues > 0 {
        score = score.wrapping_sub(30.min(int(input.kev_issues).wrapping_mul(15)));
        notes.push(format!("{} actively exploited CISA KEV vulnerability(ies)", input.kev_issues));
        guidance.push("Apply patches for CISA Known Exploited Vulnerabilities.");
    }
    if input.overdue_issues > 0 {
        score = score.wrapping_sub(40.min(int(input.overdue_issues).wrapping_mul(10)));
        notes.push(format!("{} vulnerability(ies) in SLA breach (overdue)", input.overdue_issues));
        guidance.push("Resolve overdue findings to maintain compliance windows.");
    }
    if input.high_issues > 5 {
        score = score.wrapping_sub(10);
        notes.push(format!("{} high severity findings in backlog", input.high_issues));
    }

    let score = score.max(0);
    let details = if notes.is_empty() {
        "All vulnerabilities are within SLA thresholds with zero unmitigated criticals.".to_owned()
    } else {
        format!("{}.", notes.join(", "))
    };
    let remediation_guidance = if guidance.is_empty() {
        "Maintain continuous vulnerability scanning and remediation cadence.".to_owned()
    } else {
        guidance.join(" ")
    };
    with_coverage(
        ControlAssessment {
            control,
            status: status_for_score(score),
            score_percentage: score,
            details,
            remediation_guidance,
        },
        input,
    )
}

/// How many targets carry a component inventory, over how many exist. **Not capped by coverage**, and rightly: it is
/// scored on a presence, so a never-scanned target already lands in the denominator and not the numerator.
fn evaluate_supply_chain(control: &'static ComplianceControl, input: &PostureInput) -> ControlAssessment {
    let total = input.total_targets.max(1);
    let with_sbom = input.targets_with_sbom;
    let ratio = round_f32((with_sbom as f32 / total as f32) * 100.0);
    let remediation_guidance = if ratio < 100 {
        "Scan the remaining targets: a target with no recorded components has no inventory to exhibit, whether it was \
         never scanned or its scan produced none."
    } else {
        "SBOM inventory is complete across all targets."
    };
    ControlAssessment {
        control,
        status: status_for_score(ratio),
        score_percentage: ratio,
        details: format!("{with_sbom}/{total} monitored targets have an active Software Bill of Materials (SBOM)."),
        remediation_guidance: remediation_guidance.to_owned(),
    }
}

fn evaluate_secrets(control: &'static ComplianceControl, input: &PostureInput) -> ControlAssessment {
    let secrets = input.secret_issues;
    let clean = secrets == 0;
    let score = if clean { 100 } else { 0.max(100i32.wrapping_sub(int(secrets).wrapping_mul(25))) };
    let assessment = ControlAssessment {
        control,
        status: if clean { Status::Compliant } else { Status::NonCompliant },
        score_percentage: score,
        details: if clean {
            "Zero exposed plaintext credentials or tokens detected.".to_owned()
        } else {
            format!("{secrets} plaintext secret(s) or API key(s) detected in source code.")
        },
        remediation_guidance: if clean {
            "Maintain automated Gitleaks pre-commit and pipeline verification."
        } else {
            "Rotate all leaked secrets immediately and purge from Git history."
        }
        .to_owned(),
    };
    with_coverage(assessment, input)
}

fn evaluate_secure_coding(control: &'static ComplianceControl, input: &PostureInput) -> ControlAssessment {
    let sast = input.sast_issues;
    let clean = sast == 0;
    let score = if clean { 100 } else { 20.max(100i32.wrapping_sub(int(sast).wrapping_mul(5))) };
    let assessment = ControlAssessment {
        control,
        status: status_for_score(score),
        score_percentage: score,
        details: if clean {
            "No high-severity static analysis (SAST) flaws identified.".to_owned()
        } else {
            format!("{sast} code quality / SAST finding(s) detected by Semgrep.")
        },
        remediation_guidance: if clean {
            "Continue enforcing automated Semgrep rules in development pipelines."
        } else {
            "Remediate static analysis findings in custom application code."
        }
        .to_owned(),
    };
    with_coverage(assessment, input)
}

fn evaluate_iac(control: &'static ComplianceControl, input: &PostureInput) -> ControlAssessment {
    let iac = input.iac_issues;
    let clean = iac == 0;
    let score = if clean { 100 } else { 30.max(100i32.wrapping_sub(int(iac).wrapping_mul(10))) };
    let assessment = ControlAssessment {
        control,
        status: status_for_score(score),
        score_percentage: score,
        details: if clean {
            "Infrastructure-as-Code manifests conform to security baselines.".to_owned()
        } else {
            format!("{iac} IaC security misconfiguration(s) detected by Checkov.")
        },
        remediation_guidance: if clean {
            "Keep IaC configurations locked to CIS security baselines."
        } else {
            "Remediate Terraform / Kubernetes / Dockerfile misconfigurations."
        }
        .to_owned(),
    };
    with_coverage(assessment, input)
}

fn evaluate_governance(control: &'static ComplianceControl, input: &PostureInput) -> ControlAssessment {
    let total = input.total_targets.max(1);
    let passing = input.gate_passing_targets;
    let score = round_f32((passing as f32 / total as f32) * 100.0);
    ControlAssessment {
        control,
        status: status_for_score(score),
        score_percentage: score,
        details: format!("{passing}/{total} monitored targets pass active Gate release policies."),
        remediation_guidance: if score < 100 {
            "Resolve blocking gate violations before deploying targets to production."
        } else {
            "All targets currently satisfy gate security policies."
        }
        .to_owned(),
    }
}

fn evaluate_audit(control: &'static ComplianceControl, input: &PostureInput) -> ControlAssessment {
    let valid = input.audit_chain_valid;
    ControlAssessment {
        control,
        status: if valid { Status::Compliant } else { Status::NonCompliant },
        score_percentage: if valid { 100 } else { 0 },
        details: if valid {
            "The audit log's SHA-256 hash chain verifies intact: no entry was modified or removed selectively."
        } else {
            "Audit log integrity check failed or tampering detected."
        }
        .to_owned(),
        remediation_guidance: if valid {
            "Audit logs are continuously sealed and tamper-evident."
        } else {
            "Investigate audit log integrity anomaly immediately."
        }
        .to_owned(),
    }
}

/// Caps a finding-based verdict by how much of the estate was looked at — `withCoverage`.
///
/// **A backlog of zero is not evidence of anything on its own**: every control scored on an absence of findings
/// (vulnerabilities, secrets, secure coding, IaC) cannot read compliant over targets nobody observed inside the
/// window. A cap rather than a penalty: unassessed is not less compliant, and the detail says which part of the
/// estate the verdict does not cover.
fn with_coverage(assessment: ControlAssessment, input: &PostureInput) -> ControlAssessment {
    let total = input.total_targets.max(1);
    let never = total.wrapping_sub(input.scanned_targets).max(0);
    let stale = input.scanned_targets.wrapping_sub(input.freshly_scanned_targets).max(0);
    if never == 0 && stale == 0 {
        return assessment;
    }

    let mut gaps = Vec::new();
    if never > 0 {
        gaps.push(format!("{never} target(s) have never been scanned"));
    }
    if stale > 0 {
        gaps.push(format!("{stale} target(s) were last scanned more than {} days ago", input.freshness_window_days));
    }

    // Never scanned is the harder failure: a stale observation is out of date, an absent one was never made.
    let status = if never > 0 { Status::NonCompliant } else { worse_of(assessment.status, Status::Partial) };
    let observed = round_f32((input.freshly_scanned_targets as f32 / total as f32) * 100.0);
    ControlAssessment {
        control: assessment.control,
        status,
        score_percentage: assessment.score_percentage.min(observed),
        details: format!(
            "{} Assessment covers {}/{total} target(s) observed within {} days — {}.",
            assessment.details,
            input.freshly_scanned_targets,
            input.freshness_window_days,
            gaps.join(", ")
        ),
        remediation_guidance: format!(
            "Scan the targets named above: a control cannot be evidenced on an estate it has not observed. {}",
            assessment.remediation_guidance
        ),
    }
}

/// The worse of two statuses, so a cap can never improve a verdict. The declared order is best to worst, so the
/// greater is the worse — written out because the opposite reading is the natural one and would whitewash.
fn worse_of(left: Status, right: Status) -> Status {
    if left >= right { left } else { right }
}

fn status_for_score(score: i32) -> Status {
    if score >= 90 {
        Status::Compliant
    } else if score >= 60 {
        Status::Partial
    } else {
        Status::NonCompliant
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLEAN: PostureInput = PostureInput {
        total_targets: 10,
        scanned_targets: 10,
        freshly_scanned_targets: 10,
        freshness_window_days: 30,
        gate_passing_targets: 10,
        critical_issues: 0,
        high_issues: 0,
        medium_issues: 0,
        low_issues: 0,
        kev_issues: 0,
        overdue_issues: 0,
        secret_issues: 0,
        sast_issues: 0,
        iac_issues: 0,
        targets_with_sbom: 10,
        audit_chain_valid: true,
    };

    fn of(results: &[ComplianceEvaluation], category: Category) -> Vec<&ControlAssessment> {
        results.iter().flat_map(|evaluation| &evaluation.controls).filter(|c| c.control.category == category).collect()
    }

    #[test]
    fn an_empty_instance_measures_nothing_but_its_own_audit_trail() {
        // `ComplianceEngineTest.anEmptyInstanceMeasuresNothing`.
        let empty = PostureInput {
            total_targets: 0,
            scanned_targets: 0,
            freshly_scanned_targets: 0,
            gate_passing_targets: 0,
            targets_with_sbom: 0,
            ..CLEAN
        };
        for evaluation in evaluate_all(&empty, &PlatformPosture::FULLY_ENABLED) {
            assert_eq!(evaluation.overall_status, Status::NoData, "{}", evaluation.framework.name());
            assert_eq!(evaluation.score_percentage, 0);
            for control in &evaluation.controls {
                let expected = if control.control.category == Category::AuditAndLogging {
                    Status::Compliant
                } else {
                    Status::NoData
                };
                assert_eq!(control.status, expected, "{}", control.control.id);
            }
        }
    }

    #[test]
    fn a_cap_never_improves_a_failing_control() {
        // `aCapNeverImprovesAnAssessment`: eight secrets and no key stay non-compliant at zero.
        let leaking = PostureInput { secret_issues: 8, ..CLEAN };
        let no_key =
            PlatformPosture { encryption_configured: false, external_kms: false, ..PlatformPosture::FULLY_ENABLED };
        let results = evaluate_all(&leaking, &no_key);
        for control in of(&results, Category::SecretsManagement) {
            assert_eq!(control.status, Status::NonCompliant);
            assert_eq!(control.score_percentage, 0);
        }
    }

    #[test]
    fn a_partly_scanned_estate_caps_every_control_scored_on_absence() {
        // `aPartlyScannedEstateCapsEveryControlScoredOnAbsence`: one of ten scanned, clean.
        let one_of_ten = PostureInput {
            scanned_targets: 1,
            freshly_scanned_targets: 1,
            gate_passing_targets: 1,
            targets_with_sbom: 1,
            ..CLEAN
        };
        let results = evaluate_all(&one_of_ten, &PlatformPosture::FULLY_ENABLED);
        for category in [
            Category::VulnerabilityManagement,
            Category::SecureCoding,
            Category::InfrastructureAsCode,
            Category::SecretsManagement,
        ] {
            for control in of(&results, category) {
                assert_eq!(control.status, Status::NonCompliant, "{}", control.control.id);
                assert_eq!(control.score_percentage, 10);
                assert!(control.details.contains(
                    "Assessment covers 1/10 target(s) observed within 30 days — 9 target(s) have never been scanned."
                ));
            }
        }
    }
}
