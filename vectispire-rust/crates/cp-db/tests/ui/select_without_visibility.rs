// The constructor takes the Visibility: leaving it out is a missing argument.
use vectispire_cp_db::query::Issues;
use vectispire_cp_db::VisibleSelect;

fn main() {
    let _ = VisibleSelect::<Issues>::count();
}
