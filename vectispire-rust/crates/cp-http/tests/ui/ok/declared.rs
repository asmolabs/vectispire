// Both answers given, in either order: the route has a handler.
use vectispire_cp_http::access::Access;
use vectispire_cp_http::principal::ApiKeyScope;
use vectispire_cp_http::routes::Route;

async fn handler() {}

fn main() {
    let _ = Route::get("/a").requires(Access::Account).names_no_target().handler(handler);
    let _ = Route::get("/b").scoped().requires(Access::WriteAccount).handler(handler);
    let _ = Route::post("/c")
        .accepts_api_key(ApiKeyScope::Scan)
        .requires(Access::WriteAccount)
        .scoped()
        .allows_pending_password_change()
        .handler(handler);
}
