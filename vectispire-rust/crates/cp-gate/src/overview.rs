//! SecurityOverview: where each target stands, in one picture.

use std::collections::HashMap;

use time::OffsetDateTime;
use vectispire_cp_db::ScanTarget;
use vectispire_domain::ScanStatus;

use crate::gate::PolicyGate;
use crate::issue::GateIssue;
use crate::observation::Observation;
use crate::resolution::{
    PolicyLookup, PolicyResolution, PolicyScopeChoice, RequestedPolicy, ResolvedPolicy, StoredPolicy,
};
use crate::verdict::{Coverage, GateVerdict, Rule};

/// A target as this screen names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedTarget {
    pub target: ScanTarget,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatestScan {
    pub id: i64,
    pub status: ScanStatus,
    pub created_at: OffsetDateTime,
}

/// Where one target stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetPosture {
    pub target: ScanTarget,
    pub name: String,
    pub verdict: GateVerdict,
    pub policy: ResolvedPolicy,
    pub observation: Observation,
    pub last_scan: Option<LatestScan>,
    pub passed: bool,
    pub observed: bool,
}

/// The entire posture overview.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Overview {
    pub targets: Vec<TargetPosture>,
    pub failing_count: i32,
    pub total_count: i32,
    pub kev_count: i64,
    pub never_scanned_count: i64,
    pub last_scan_failed_count: i64,
}

/// Everything the screen needs, already read.
#[derive(Debug)]
pub struct Input {
    pub targets: Vec<NamedTarget>,
    pub policies_by_target: HashMap<ScanTarget, StoredPolicy>,
    pub global_policy: Option<StoredPolicy>,
    pub open_issues: HashMap<ScanTarget, Vec<GateIssue>>,
    pub latest_scans: HashMap<ScanTarget, LatestScan>,
    pub latest_finished_scans: HashMap<ScanTarget, LatestScan>,
    pub uncovered_ecosystems: HashMap<ScanTarget, Vec<String>>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SecurityOverview;

impl SecurityOverview {
    pub fn build(input: Input) -> Overview {
        let mut postures = Vec::with_capacity(input.targets.len());
        for named in &input.targets {
            postures.push(Self::posture(named, &input));
        }

        let failing_count = i32::try_from(postures.iter().filter(|p| !p.passed).count()).unwrap_or(0);
        let total_count = i32::try_from(postures.len()).unwrap_or(0);
        let kev_count =
            i64::try_from(postures.iter().flat_map(|p| &p.verdict.violations).filter(|v| v.rule == Rule::Kev).count())
                .unwrap_or(0);
        let never_scanned_count =
            i64::try_from(postures.iter().filter(|p| p.observation == Observation::NeverScanned).count()).unwrap_or(0);
        let last_scan_failed_count =
            i64::try_from(postures.iter().filter(|p| p.observation == Observation::LastScanFailed).count())
                .unwrap_or(0);

        Overview {
            targets: postures,
            failing_count,
            total_count,
            kev_count,
            never_scanned_count,
            last_scan_failed_count,
        }
    }

    fn posture(named: &NamedTarget, input: &Input) -> TargetPosture {
        let lookup = PolicyLookup {
            for_target: input.policies_by_target.get(&named.target).cloned(),
            global: input.global_policy.clone(),
        };
        let policy = PolicyResolution::resolve(lookup, &RequestedPolicy::none(), PolicyScopeChoice::Target);

        let latest = input.latest_scans.get(&named.target).cloned();
        let observation = Observation::of(latest.as_ref().map(|s| s.status));

        let open_issues = input.open_issues.get(&named.target).cloned().unwrap_or_default();
        let uncovered = input.uncovered_ecosystems.get(&named.target).cloned().unwrap_or_default();
        let finished_obs = Observation::of(input.latest_finished_scans.get(&named.target).map(|s| s.status));

        let verdict = PolicyGate::evaluate(&open_issues, &policy.policy, &Coverage::new(uncovered), Some(finished_obs));

        let passed = verdict.passed;
        let observed = observation.examined();

        TargetPosture {
            target: named.target,
            name: named.name.clone(),
            verdict,
            policy,
            observation,
            last_scan: latest,
            passed,
            observed,
        }
    }
}
