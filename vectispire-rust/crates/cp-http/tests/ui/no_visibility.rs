// A marker is not authorization: a route that says who may call it but not how it handles visibility has no handler.
use vectispire_cp_http::access::Access;
use vectispire_cp_http::routes::Route;

async fn handler() {}

fn main() {
    let _ = Route::get("/x").requires(Access::Account).handler(handler);
}
