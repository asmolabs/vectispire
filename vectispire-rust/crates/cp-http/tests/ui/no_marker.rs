// A route that names no target but never says who may call it: no `.requires(..)`, no `.handler`.
use vectispire_cp_http::routes::Route;

async fn handler() {}

fn main() {
    let _ = Route::get("/x").names_no_target().handler(handler);
}
