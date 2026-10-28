//! `RequestActors`: the name a route's audit entry is attributed to. Java keeps it beside the markers in
//! `access.web.security`, so a route that names no target still reaches `access::security` for it.

use vectispire_cp_http::Principal;

/// `RequestActors.of(principal, request, fallback)`'s name: the signed-in account's — an integration key writes in
/// its account's name, the key named beside it (decision 0024), which the credential's resolution wrote into the
/// principal — or `fallback` when the principal names none. The fallback is the route's: each keeps the one it has
/// always written, because changing it would change how past and future entries compare.
pub fn actor_name(principal: &Principal, fallback: &str) -> String {
    principal.actor().unwrap_or_else(|| fallback.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vectispire_cp_http::Grounds;
    use vectispire_cp_http::principal::Account;

    #[test]
    fn the_account_is_named_and_the_fallback_only_without_one() {
        let account = Account { username: "lead".into(), role: None, must_change_password: false };
        assert_eq!(actor_name(&Principal::session(account.clone()), "system"), "lead");
        let keyed = Principal::session(account)
            .with_grounds(Grounds { actor: Some("lead (key ci)".into()), ..Grounds::default() });
        assert_eq!(actor_name(&keyed, "system"), "lead (key ci)");
        assert_eq!(actor_name(&Principal::agent("agent-1"), "system"), "system");
    }
}
