// Nothing declared at all.
use vectispire_cp_http::routes::Route;

async fn handler() {}

fn main() {
    let _ = Route::get("/x").handler(handler);
}
