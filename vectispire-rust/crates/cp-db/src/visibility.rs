//! Which targets a reader may see — the value every query on a target's rows must be handed.
//!
//! A port of `common.domain.access.Visibility` and `ScanTarget`, kept to what a query needs. **It lives
//! here until `cp-access` exists**, which resolves it from the account's grants and the credential's
//! restriction (`VisibilityService.of`); this crate only applies it, and has no way to make one up
//! beyond [`Visibility::everything`] — which is the answer `VisibilityService` itself gives an
//! administrator or an unrestricted installation.

use std::collections::BTreeSet;

/// A repository or a container image: the two things a scan examines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScanTarget {
    Repository(i64),
    Container(i64),
}

/// Everything, or only these targets.
///
/// **`Only` with no target is an answer, not an absence**: a reader granted nothing sees nothing, and
/// a query handed it matches no row. Treating it as "no restriction" is the one mistake this type
/// exists to make impossible — `asFilter()` on the Java side returns `Optional.empty()` only for
/// `Everything`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Visibility {
    Everything,
    Only(BTreeSet<ScanTarget>),
}

impl Visibility {
    pub fn everything() -> Visibility {
        Visibility::Everything
    }

    pub fn only(targets: impl IntoIterator<Item = ScanTarget>) -> Visibility {
        Visibility::Only(targets.into_iter().collect())
    }

    pub fn permits(&self, target: ScanTarget) -> bool {
        match self {
            Visibility::Everything => true,
            Visibility::Only(targets) => targets.contains(&target),
        }
    }

    pub fn is_empty(&self) -> bool {
        matches!(self, Visibility::Only(targets) if targets.is_empty())
    }

    /// What both allow — the account's grant narrowed by the credential's restriction.
    pub fn and(&self, other: &Visibility) -> Visibility {
        match (self, other) {
            (Visibility::Everything, other) | (other, Visibility::Everything) => other.clone(),
            (Visibility::Only(mine), Visibility::Only(theirs)) => {
                Visibility::Only(mine.intersection(theirs).copied().collect())
            }
        }
    }

    pub(crate) fn split(targets: &BTreeSet<ScanTarget>) -> (Vec<i64>, Vec<i64>) {
        let mut repositories = Vec::new();
        let mut containers = Vec::new();
        for target in targets {
            match target {
                ScanTarget::Repository(id) => repositories.push(*id),
                ScanTarget::Container(id) => containers.push(*id),
            }
        }
        (repositories, containers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ScanTarget::{Container, Repository};

    #[test]
    fn nothing_granted_permits_nothing() {
        let none = Visibility::only([]);
        assert!(none.is_empty());
        assert!(!none.permits(Repository(1)));
        assert!(Visibility::everything().permits(Container(7)));
        assert!(!Visibility::everything().is_empty());
    }

    #[test]
    fn two_visibilities_meet_on_what_both_allow() {
        let account = Visibility::only([Repository(1), Repository(2), Container(3)]);
        let credential = Visibility::only([Repository(2), Container(3), Container(4)]);
        assert_eq!(account.and(&credential), Visibility::only([Repository(2), Container(3)]));
        assert_eq!(Visibility::everything().and(&credential), credential);
        assert_eq!(account.and(&Visibility::everything()), account);
        assert!(account.and(&Visibility::only([])).is_empty());
    }
}
