// A second marker is refused, so a route cannot quietly carry two answers to one question.
use vectispire_cp_http::access::Access;
use vectispire_cp_http::routes::Route;

fn main() {
    let _ = Route::get("/x").requires(Access::Account).requires(Access::Administrator);
}
