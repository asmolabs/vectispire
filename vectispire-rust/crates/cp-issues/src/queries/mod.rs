//! The named interface `issues::queries` exposed for other modules:
//! criteria and filters for backlog queries, and `IssueCatalog`.

pub use crate::catalog::*;
pub use crate::persistence::aggregates::{
    Axis, GraphNode, Observation, OpenBacklog, PackageDetail, PackageWeight, ResolvedDuration, SeverityTypeCount,
    TargetGradingCount, TargetResolutions, TypePackaging,
};
pub use crate::persistence::{IssueFilters, Lifetime};
