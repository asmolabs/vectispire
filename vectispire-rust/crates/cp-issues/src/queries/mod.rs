//! The named interface `issues::queries` exposed for other modules:
//! criteria and filters for backlog queries, and `IssueCatalog`.

pub use crate::catalog::*;
pub use crate::persistence::aggregates::{
    Axis, GraphNode, Identified, Observation, OpenBacklog, OwaspCategoryCount, PackageDetail, PackageWeight,
    Resolution, ResolvedDuration, SeverityTypeCount, TargetBreakdown, TargetGradingCount, TargetResolutions,
    TypePackaging, WeeklyFlow,
};
pub use crate::persistence::{IssueFilters, Lifetime};
