// The list of target tables is sealed, beside the rule that reads it: another module cannot declare a
// table of target rows that bypasses it — adding one is a change to this crate, and a review.
use vectispire_cp_db::query::{TargetColumns, TargetTable};

struct Mine;

impl TargetTable for Mine {
    const TABLE: &'static str = "t_mine";
    const TARGET: TargetColumns = TargetColumns::Repository("id");
}

fn main() {}
