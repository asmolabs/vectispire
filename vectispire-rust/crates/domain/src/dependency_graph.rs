//! `DependencyGraph` and `Directness`: which dependencies the project actually asked for.

/// Whether the project asked for a dependency, or something else dragged it in.
///
/// Three states, and [`Directness::Unknown`] is the one that matters: an `Option<bool>` spells the same
/// three, but nothing stops a caller reading absence as `false` — "we do not know" turned into
/// "transitive", on the very field meant to decide what to fix first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Directness {
    /// Declared in the project's own manifest: fixable this afternoon by changing one line.
    Direct,
    /// Pulled in by something else: waits on an upstream release, a pin, a fork or an accepted risk.
    Transitive,
    /// The SBOM did not say. Not a synonym for [`Directness::Transitive`].
    Unknown,
}

impl Directness {
    /// `Directness.of(boolean)`.
    pub fn of(direct: bool) -> Directness {
        if direct { Directness::Direct } else { Directness::Transitive }
    }

    /// The label in exports and tickets — empty, not "unknown", when nothing is known: a column filled
    /// with the word reads as a finding about the dependency.
    pub fn label(self) -> &'static str {
        match self {
            Directness::Direct => "direct",
            Directness::Transitive => "transitive",
            Directness::Unknown => "",
        }
    }
}
