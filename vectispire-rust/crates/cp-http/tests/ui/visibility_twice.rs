// A route cannot be both scoped and naming no target.
use vectispire_cp_http::routes::Route;

fn main() {
    let _ = Route::get("/x").scoped().names_no_target();
}
