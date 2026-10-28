// The fields are private: a VisibleSelect cannot be assembled around a statement that never saw a
// Visibility.
use sea_query::Query;
use vectispire_cp_db::query::Issues;
use vectispire_cp_db::VisibleSelect;

fn main() {
    let _ = VisibleSelect::<Issues> { statement: Query::select(), table: std::marker::PhantomData };
}
