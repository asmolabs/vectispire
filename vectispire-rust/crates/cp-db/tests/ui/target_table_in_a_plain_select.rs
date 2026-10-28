// A target table is a marker, not an identifier sea-query can put in a FROM: a hand-built SELECT on it
// does not compile, so the only way to read the table is through VisibleSelect.
use sea_query::Query;
use vectispire_cp_db::query::Issues;

fn main() {
    let mut select = Query::select();
    select.from(Issues);
}
