//! The sign-in services over doubles — `AuthServiceTest` case by case, then what `AuthenticationFlowService`,
//! `TotpService`, `SignInMethodPolicy`, `RateWindows` and `SessionCleanupService` decide, in the order they decide it.
//! The same services on real databases, under concurrency, are `sign_in_on_both_engines.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod sign_in_support;

use std::sync::Arc;

use sign_in_support::{Doors, HandClock, Memory, NOW, PASSWORD, account, flow, flow_with};
use time::Duration;
use vectispire_cp_access::accounts::{AuditOperation, PasswordChange, Sealed};
use vectispire_cp_access::credentials::hash_of;
use vectispire_cp_access::login_throttle::{
    MAX_ATTEMPTS_PER_CLIENT, MAX_ATTEMPTS_PER_USER, MAX_SECOND_FACTOR_FAILURES, account_key, client_key,
    second_factor_key, user_key,
};
use vectispire_cp_access::rate_windows::{Limit, RateWindows};
use vectispire_cp_access::second_factor::{
    ALREADY_ENABLED, INVALID_DISABLE_CODE, INVALID_ENROLMENT_CODE, LOCKED, SecondFactorError, backup_context,
    secret_context,
};
use vectispire_cp_access::session_cleanup::{ATTEMPT_RETENTION, CleanupResult, SessionCleanup, SessionCleanupTask};
use vectispire_cp_access::sign_in::{
    Handoff, LoginOutcome, LoginRequest, MAX_MFA_CHALLENGES, SignIn, SignInMethodPolicy, SignInOptions, Verification,
};
use vectispire_cp_access::throttle::{SharedClock, Throttle};
use vectispire_cp_access::totp;
use vectispire_cp_maintenance::{MaintenanceTask, Sequence};

fn clock() -> Arc<HandClock> {
    HandClock::at(NOW)
}

fn shared(clock: &Arc<HandClock>) -> SharedClock {
    clock.clone()
}

fn request<'a>(username: &'a str, password: &'a str) -> LoginRequest<'a> {
    LoginRequest { username, password, user_agent: Some("curl/8"), ip_address: Some("10.0.0.1") }
}

// ── AuthServiceTest ──────────────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn opens_a_session_on_the_right_password() {
    let clock = clock();
    let (flow, store, _, doors) = flow(shared(&clock));
    store.add(account(1, "alice", true));

    let result = flow.login(&request("alice", PASSWORD)).await.unwrap();
    let LoginOutcome::Success { issued, .. } = result.outcome else { panic!("{:?}", result.outcome) };
    assert_eq!(issued.session.token_hash, hash_of(issued.token.expose()));
    assert_eq!(
        doors.opened(),
        vec![sign_in_support::Opened {
            user_id: 1,
            user_agent: Some("curl/8".into()),
            ip_address: Some("10.0.0.1".into())
        }]
    );
    assert_eq!(result.audit.operation, AuditOperation::LoginSuccess);
    assert_eq!((result.audit.resource.as_str(), result.audit.description.as_str()), ("alice", "Login succeeded"));
    assert_eq!(result.audit.username.as_deref(), Some("alice"));
    // A success clears the account's and the name's counters.
    let cleared = store.state().cleared_keys.clone();
    assert!(cleared.contains(&account_key(1)), "{cleared:?}");
    assert!(cleared.contains(&user_key("alice")), "{cleared:?}");
}

/// The audit of 10 October 2026: a success erased the address's counter too.
#[tokio::test]
async fn a_success_keeps_the_address_s_failures_and_takes_back_only_its_own_attempt() {
    let clock = clock();
    let (flow, store, _, _) = flow(shared(&clock));
    store.add(account(1, "alice", true));
    store.seed_attempts(&client_key("10.0.0.1"), 2, NOW);

    flow.login(&request("alice", PASSWORD)).await.unwrap();

    assert!(!store.state().cleared_keys.contains(&client_key("10.0.0.1")));
    assert_eq!(
        store.attempts_under(&client_key("10.0.0.1")),
        2,
        "the address keeps its two, and the success left none"
    );
    assert_eq!(store.state().deleted_id_batches.len(), 1, "its own rows taken back in one statement");
    assert_eq!(store.state().attempts.len(), 2, "nothing else is left");
}

#[tokio::test]
async fn a_wrong_password_an_unknown_account_and_a_disabled_one_are_one_outcome() {
    let clock = clock();
    let (flow, store, _, _) = flow(shared(&clock));
    store.add(account(1, "alice", true));
    store.add(account(2, "bob", false));

    for (name, password) in [("alice", "wrong"), ("nobody", PASSWORD), ("bob", PASSWORD)] {
        let result = flow.login(&request(name, password)).await.unwrap();
        assert!(matches!(result.outcome, LoginOutcome::Invalid), "{name}: {:?}", result.outcome);
        assert_eq!(result.audit.operation, AuditOperation::LoginFailure);
        assert_eq!((result.audit.resource.as_str(), result.audit.description.as_str()), (name, "Login failed"));
        assert_eq!(result.audit.signal, None);
    }
}

#[tokio::test]
async fn a_failure_counts_against_the_account_and_against_the_caller_s_address() {
    let clock = clock();
    let (flow, store, _, _) = flow(shared(&clock));
    store.add(account(1, "alice", true));

    flow.login(&request("alice", "wrong")).await.unwrap();
    flow.login(&request("nobody", "wrong")).await.unwrap();

    // In the order Java's LinkedHashMap holds them: the account, the name, the address.
    assert_eq!(
        store.state().recorded,
        vec![account_key(1), user_key("alice"), client_key("10.0.0.1"), user_key("nobody"), client_key("10.0.0.1"),]
    );
    // An admitted failure keeps its rows.
    assert_eq!(store.state().attempts.len(), 5);
}

#[tokio::test]
async fn an_absent_address_is_counted_under_the_four_letters() {
    let clock = clock();
    let (flow, store, _, _) = flow(shared(&clock));
    flow.login(&LoginRequest { username: "nobody", password: "x", user_agent: None, ip_address: None }).await.unwrap();
    assert_eq!(store.state().recorded, vec![user_key("nobody"), client_key("null")]);
}

#[tokio::test]
async fn a_spelling_the_database_would_resolve_to_an_account_opens_nothing_and_meets_the_folded_counter() {
    let clock = clock();
    let (flow, store, _, _) = flow(shared(&clock));
    store.add(account(1, "alice", true));
    store.state().aliases.insert("ÀLICE".into(), 1);

    let result = flow.login(&request("ÀLICE", PASSWORD)).await.unwrap();
    assert!(matches!(result.outcome, LoginOutcome::Invalid));
    assert!(!store.state().lookups.contains(&"ÀLICE".to_owned()), "never looked up");

    store.seed_attempts(&user_key("alice"), MAX_ATTEMPTS_PER_USER, NOW);
    assert!(matches!(flow.login(&request("ÀLICE", PASSWORD)).await.unwrap().outcome, LoginOutcome::Blocked(_)));
}

#[tokio::test]
async fn a_character_the_collation_ignores_opens_no_account_so_the_lockout_tells_nothing() {
    let clock = clock();
    let (flow, store, _, _) = flow(shared(&clock));
    let typed = "ali\u{AD}ce";
    store.add(account(1, "alice", true));
    store.state().aliases.insert(typed.into(), 1);
    store.seed_attempts(&account_key(1), MAX_ATTEMPTS_PER_USER, NOW);

    let result = flow.login(&request(typed, PASSWORD)).await.unwrap();
    assert!(matches!(result.outcome, LoginOutcome::Invalid), "answered as an unknown name: {:?}", result.outcome);
    assert!(!store.state().lookups.contains(&typed.to_owned()));
    let recorded = store.state().recorded.clone();
    assert!(!recorded.contains(&account_key(1)) && recorded.contains(&user_key(typed)), "{recorded:?}");
}

#[tokio::test]
async fn an_unknown_name_meets_the_same_folded_counter_as_an_account() {
    let clock = clock();
    let (flow, store, _, _) = flow(shared(&clock));
    store.add(account(1, "alice", true));
    store.seed_attempts(&user_key("alice"), MAX_ATTEMPTS_PER_USER, NOW);

    assert_eq!(user_key("Àlice"), user_key("alice"));
    assert!(matches!(flow.login(&request("Àlice", PASSWORD)).await.unwrap().outcome, LoginOutcome::Blocked(_)));
    assert!(matches!(flow.login(&request("alice", PASSWORD)).await.unwrap().outcome, LoginOutcome::Blocked(_)));
}

#[tokio::test]
async fn a_throttled_attempt_costs_no_password_verification_at_all() {
    let clock = clock();
    let (flow, store, _, doors) = flow(shared(&clock));
    let mut stale = account(1, "alice", true);
    stale.password = Some(vectispire_cp_access::accounts::PasswordHash::new(
        vectispire_cp_access::passwords::hash_with(PASSWORD, 4096, 1, 1).unwrap(),
    ));
    store.add(stale);
    store.seed_attempts(&account_key(1), MAX_ATTEMPTS_PER_USER, NOW);

    let result = flow.login(&request("alice", PASSWORD)).await.unwrap();
    let LoginOutcome::Blocked(wait) = result.outcome else { panic!("{:?}", result.outcome) };
    // The oldest of the five is ten seconds old: fourteen minutes and fifty seconds to wait.
    assert_eq!(wait, Duration::seconds(890));
    assert_eq!(result.audit.operation, AuditOperation::LoginBlocked);
    assert_eq!(result.audit.description, "Attempt refused by the throttle (890s to wait)");
    assert_eq!((result.audit.resource.as_str(), result.audit.username.as_deref()), ("alice", Some("alice")));
    assert_eq!(result.audit.signal, Some("SIGN_IN_THROTTLED"));
    assert!(doors.opened().is_empty(), "no session");
    assert!(store.state().rehashed.is_empty(), "no rehash: the hash was never compared");
    // Refused, it took its rows back: being refused does not extend the lockout.
    assert_eq!(store.state().attempts.len(), MAX_ATTEMPTS_PER_USER);
}

#[tokio::test]
async fn the_strictest_ceiling_decides_the_client_s_too() {
    let clock = clock();
    let (flow, store, _, _) = flow(shared(&clock));
    store.seed_attempts(&client_key("10.0.0.1"), MAX_ATTEMPTS_PER_CLIENT - 1, NOW);
    assert!(matches!(flow.login(&request("nobody", "x")).await.unwrap().outcome, LoginOutcome::Invalid));
    assert!(matches!(flow.login(&request("someone", "x")).await.unwrap().outcome, LoginOutcome::Blocked(_)));
}

#[tokio::test]
async fn a_stale_hash_is_rewritten_on_the_way_in() {
    let clock = clock();
    let (flow, store, _, _) = flow(shared(&clock));
    let mut stale = account(1, "alice", true);
    stale.password = Some(vectispire_cp_access::accounts::PasswordHash::new(
        vectispire_cp_access::passwords::hash_with(PASSWORD, 4096, 1, 1).unwrap(),
    ));
    store.add(stale);
    assert!(matches!(flow.login(&request("alice", PASSWORD)).await.unwrap().outcome, LoginOutcome::Success { .. }));
    assert_eq!(store.state().rehashed, vec![1]);
}

#[tokio::test]
async fn an_unknown_name_costs_the_same_key_derivation_as_a_known_one() {
    let clock = clock();
    let (flow, store, _, _) = flow(shared(&clock));
    store.add(account(1, "alice", true));
    flow.login(&request("alice", "warm-up")).await.unwrap();
    let (mut known, mut unknown) = (std::time::Duration::MAX, std::time::Duration::MAX);
    for run in 0..3 {
        // A fresh window each run, so the throttle never refuses before the derivation.
        store.state().attempts.clear();
        let started = std::time::Instant::now();
        flow.login(&request("alice", "wrong")).await.unwrap();
        known = known.min(started.elapsed());
        let started = std::time::Instant::now();
        flow.login(&request(&format!("nobody-{run}"), "wrong")).await.unwrap();
        unknown = unknown.min(started.elapsed());
    }
    assert!(unknown > known / 3, "{unknown:?} for an unknown name, against {known:?} for a known one");
}

#[tokio::test]
async fn an_account_that_owes_a_code_gets_no_session_from_its_password() {
    let clock = clock();
    let (flow, store, _, doors) = flow(shared(&clock));
    let mut carol = account(3, "carol", true);
    carol.mfa_enabled = true;
    store.add(carol);

    let result = flow.login(&request("carol", PASSWORD)).await.unwrap();
    assert!(matches!(result.outcome, LoginOutcome::SecondFactorRequired(_)));
    assert_eq!(result.audit.description, "Password accepted, second factor required");
    assert!(doors.opened().is_empty());
}

// ── AuthenticationFlowService.signIn ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn password_sign_in_switched_off_is_refused_and_recorded() {
    let clock = clock();
    let (flow, store, log, _) = flow_with(shared(&clock), SignInMethodPolicy::new(true, false), None);
    store.add(account(1, "alice", true));
    assert!(matches!(flow.sign_in(&request("alice", PASSWORD)).await.unwrap(), SignIn::PasswordDisabled));
    let entry = log.last();
    assert_eq!(entry.operation, AuditOperation::LoginBlocked);
    assert_eq!(entry.description, "Password sign-in is disabled on this deployment");
    assert_eq!((entry.ip_address.as_deref(), entry.user_agent.as_deref()), (Some("10.0.0.1"), Some("curl/8")));
    assert_eq!(entry.signal, None, "not the throttle's event");
    assert!(store.state().recorded.is_empty(), "nothing counted");
}

#[tokio::test]
async fn the_login_s_entry_is_recorded_with_the_caller_s_address_and_its_signal() {
    let clock = clock();
    let (flow, store, log, _) = flow(shared(&clock));
    store.seed_attempts(&user_key("alice"), MAX_ATTEMPTS_PER_USER, NOW);
    let SignIn::Throttled(wait) = flow.sign_in(&request("alice", PASSWORD)).await.unwrap() else { panic!() };
    assert_eq!(wait, Duration::seconds(890));
    let entry = log.last();
    assert_eq!(entry.signal, Some("SIGN_IN_THROTTLED"), "carried across");
    assert_eq!((entry.ip_address.as_deref(), entry.user_agent.as_deref()), (Some("10.0.0.1"), Some("curl/8")));

    assert!(matches!(flow.sign_in(&request("nobody", "x")).await.unwrap(), SignIn::Refused));
    let SignIn::SignedIn { .. } = ({
        store.add(account(1, "bob", true));
        flow.sign_in(&request("bob", PASSWORD)).await.unwrap()
    }) else {
        panic!()
    };
}

fn mfa_account(store: &Memory, id: i64, name: &str) {
    let mut user = account(id, name, true);
    user.mfa_enabled = true;
    store.add(user);
}

#[tokio::test]
async fn a_challenge_is_stored_by_its_hash_for_five_minutes_with_the_caller_s_agent() {
    let clock = clock();
    let (flow, store, _, doors) = flow(shared(&clock));
    mfa_account(&store, 3, "carol");

    let SignIn::ChallengeIssued(token) = flow.sign_in(&request("carol", PASSWORD)).await.unwrap() else { panic!() };
    assert!(uuid::Uuid::try_parse(token.expose()).is_ok(), "a random UUID's text");
    let state = store.state();
    assert!(!state.challenges.contains_key(token.expose()), "never the token itself");
    let stored = state.challenges.get(&hash_of(token.expose())).expect("stored under its hash");
    assert_eq!((stored.user_id, stored.attempts), (3, 0));
    assert_eq!(stored.expires_at, NOW + Duration::seconds(300));
    assert_eq!((stored.user_agent.as_deref(), stored.ip_address.as_deref()), (Some("curl/8"), Some("10.0.0.1")));
    assert_eq!(state.swept_at, vec![NOW], "swept before the count");
    assert!(doors.opened().is_empty());
}

#[tokio::test]
async fn a_locked_second_factor_issues_no_challenge() {
    let clock = clock();
    let (flow, store, _, _) = flow(shared(&clock));
    mfa_account(&store, 3, "carol");
    store.seed_attempts(&second_factor_key(3), MAX_SECOND_FACTOR_FAILURES, NOW);
    let SignIn::Throttled(wait) = flow.sign_in(&request("carol", PASSWORD)).await.unwrap() else { panic!() };
    assert_eq!(wait, Duration::seconds(890));
    assert!(store.state().challenges.is_empty());
}

#[tokio::test]
async fn ten_thousand_live_challenges_saturate() {
    let clock = clock();
    let (flow, store, _, _) = flow(shared(&clock));
    mfa_account(&store, 3, "carol");
    store.state().live_override = Some(MAX_MFA_CHALLENGES);
    assert!(matches!(flow.sign_in(&request("carol", PASSWORD)).await.unwrap(), SignIn::ChallengesSaturated));
    assert!(store.state().challenges.is_empty());
    store.state().live_override = Some(MAX_MFA_CHALLENGES - 1);
    assert!(matches!(flow.sign_in(&request("carol", PASSWORD)).await.unwrap(), SignIn::ChallengeIssued(_)));
}

// ── AuthenticationFlowService.verify ─────────────────────────────────────────────────────────────────────────

/// An account enrolled with a real secret at `NOW`; answers the secret and the challenge's token.
async fn enrolled_and_challenged(
    flow: &sign_in_support::Flow,
    store: &Memory,
    clock: &HandClock,
) -> (String, String, Vec<String>) {
    store.add(account(3, "carol", true));
    let secret = totp::generate_secret();
    let codes = flow
        .second_factor()
        .enable(3, &secret, &totp::generate_code(&secret, NOW).unwrap())
        .await
        .unwrap()
        .into_iter()
        .map(|code| code.expose().to_owned())
        .collect();
    let _ = clock;
    let SignIn::ChallengeIssued(token) = flow.sign_in(&request("carol", PASSWORD)).await.unwrap() else { panic!() };
    (secret, token.expose().to_owned(), codes)
}

#[tokio::test]
async fn a_right_code_opens_a_session_with_the_challenge_s_agent_and_clears_the_budget() {
    let clock = clock();
    let (flow, store, log, doors) = flow(shared(&clock));
    let (secret, token, _) = enrolled_and_challenged(&flow, &store, &clock).await;
    store.seed_attempts(&second_factor_key(3), 2, NOW);

    let code = totp::generate_code(&secret, NOW + Duration::seconds(30)).unwrap();
    let outcome = flow.verify(&token, &code, Some("other-agent"), Some("192.0.2.9")).await.unwrap();
    let Verification::Verified { user, .. } = outcome else { panic!("{outcome:?}") };
    assert_eq!(user.username, "carol");
    assert_eq!(
        doors.opened(),
        vec![sign_in_support::Opened {
            user_id: 3,
            user_agent: Some("curl/8".into()),
            ip_address: Some("10.0.0.1".into())
        }]
    );
    assert!(store.state().challenges.is_empty(), "the challenge is spent");
    assert_eq!(store.attempts_under(&second_factor_key(3)), 0, "a right code clears the budget");
    let entry = log.last();
    assert_eq!(entry.operation, AuditOperation::LoginSuccess);
    assert_eq!(entry.description, "Signed in with MFA / TOTP: carol");
    assert_eq!((entry.ip_address.as_deref(), entry.user_agent.as_deref()), (Some("192.0.2.9"), Some("other-agent")));
}

#[tokio::test]
async fn an_unknown_or_expired_challenge_is_refused_and_discarded() {
    let clock = clock();
    let (flow, store, _, _) = flow(shared(&clock));
    let (_, token, _) = enrolled_and_challenged(&flow, &store, &clock).await;
    assert!(matches!(
        flow.verify("no-such-token", "000000", None, None).await.unwrap(),
        Verification::ChallengeInvalid
    ));

    clock.advance(Duration::seconds(300));
    assert_eq!(store.state().challenges.len(), 1, "still there at its last instant");
    clock.advance(Duration::microseconds(1));
    assert!(matches!(flow.verify(&token, "000000", None, None).await.unwrap(), Verification::ChallengeInvalid));
    assert!(store.state().challenges.is_empty(), "an expired challenge goes");
    assert_eq!(store.attempts_under(&second_factor_key(3)), 0, "and costs the account nothing");
}

#[tokio::test]
async fn a_challenge_at_its_last_instant_is_still_answered() {
    let clock = clock();
    let (flow, store, _, _) = flow(shared(&clock));
    let (_, token, _) = enrolled_and_challenged(&flow, &store, &clock).await;
    clock.advance(Duration::seconds(300));
    assert!(matches!(flow.verify(&token, "000000", None, None).await.unwrap(), Verification::WrongCode));
}

#[tokio::test]
async fn a_deactivated_account_is_refused_like_a_missing_one_and_the_challenge_goes() {
    let clock = clock();
    let (flow, store, _, _) = flow(shared(&clock));
    let (secret, token, _) = enrolled_and_challenged(&flow, &store, &clock).await;
    store.state().users.get_mut(&3).unwrap().is_active = false;
    let code = totp::generate_code(&secret, NOW + Duration::seconds(30)).unwrap();
    assert!(matches!(flow.verify(&token, &code, None, None).await.unwrap(), Verification::AccountMissing));
    assert!(store.state().challenges.is_empty());
}

#[tokio::test]
async fn three_wrong_codes_destroy_the_challenge_and_the_fourth_finds_nothing() {
    let clock = clock();
    let (flow, store, log, _) = flow(shared(&clock));
    let (secret, token, _) = enrolled_and_challenged(&flow, &store, &clock).await;

    for presentation in 1..=3 {
        assert!(matches!(
            flow.verify(&token, "000000", None, Some("192.0.2.9")).await.unwrap(),
            Verification::WrongCode
        ));
        let entry = log.last();
        assert_eq!(entry.operation, AuditOperation::LoginFailure);
        assert_eq!(entry.ip_address.as_deref(), Some("192.0.2.9"));
        if presentation < 3 {
            assert_eq!(entry.description, "Invalid MFA verification code attempt");
            assert_eq!(entry.signal, None);
            assert_eq!(store.state().challenges.values().next().unwrap().attempts, presentation);
        } else {
            assert_eq!(entry.description, "MFA challenge destroyed after 3 invalid verification codes");
            assert_eq!(entry.signal, Some("MFA_FAILURE_CEILING"));
            assert!(store.state().challenges.is_empty(), "destroyed on the last try");
        }
    }
    let right = totp::generate_code(&secret, NOW + Duration::seconds(30)).unwrap();
    assert!(matches!(flow.verify(&token, &right, None, None).await.unwrap(), Verification::ChallengeInvalid));
}

#[tokio::test]
async fn a_challenge_presented_a_fourth_time_is_refused_before_its_code() {
    let clock = clock();
    let (flow, store, _, doors) = flow(shared(&clock));
    let (secret, token, _) = enrolled_and_challenged(&flow, &store, &clock).await;
    // Three presentations counted by others that raced this one, none of which has destroyed it yet.
    store.state().challenges.values_mut().next().unwrap().attempts = 3;
    let right = totp::generate_code(&secret, NOW + Duration::seconds(30)).unwrap();
    assert!(matches!(flow.verify(&token, &right, None, None).await.unwrap(), Verification::ChallengeInvalid));
    assert!(store.state().challenges.is_empty());
    assert!(doors.opened().is_empty());
    assert_eq!(store.attempts_under(&second_factor_key(3)), 0, "refused before the account's budget is spent");
}

#[tokio::test]
async fn the_account_s_budget_spans_challenges_and_locks_with_the_signal() {
    let clock = clock();
    let (flow, store, log, _) = flow(shared(&clock));
    let (secret, token, _) = enrolled_and_challenged(&flow, &store, &clock).await;
    store.seed_attempts(&second_factor_key(3), MAX_SECOND_FACTOR_FAILURES - 1, NOW);

    // The fifth wrong code is admitted, and locks the account: said in the entry, with the ceiling's event.
    assert!(matches!(flow.verify(&token, "000000", None, None).await.unwrap(), Verification::WrongCode));
    let entry = log.last();
    assert_eq!(entry.description, "Invalid MFA verification code attempt; second factor locked for this account");
    assert_eq!(entry.signal, Some("MFA_FAILURE_CEILING"));

    // The next presentation is throttled, and its challenge discarded — a right code included.
    let right = totp::generate_code(&secret, NOW + Duration::seconds(30)).unwrap();
    let outcome = flow.verify(&token, &right, None, None).await.unwrap();
    let Verification::Throttled(wait) = outcome else { panic!("{outcome:?}") };
    assert_eq!(wait, Duration::seconds(890));
    assert!(store.state().challenges.is_empty());
    assert_eq!(
        store.attempts_under(&second_factor_key(3)),
        MAX_SECOND_FACTOR_FAILURES,
        "the refusal took its row back"
    );
}

// ── exchange, options, change of password ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_hand_off_is_exchanged_once_and_never_for_a_deactivated_account() {
    let clock = clock();
    let (flow, store, _, doors) = flow(shared(&clock));
    store.add(account(1, "alice", true));
    store.add(account(2, "bob", false));
    doors.hand_off("alice-cookie", 1);
    doors.hand_off("bob-cookie", 2);

    let Handoff::Exchanged { user, .. } = flow.exchange("alice-cookie").await.unwrap() else { panic!() };
    assert_eq!(user.username, "alice");
    assert!(matches!(flow.exchange("alice-cookie").await.unwrap(), Handoff::Expired));
    assert!(matches!(flow.exchange("bob-cookie").await.unwrap(), Handoff::AccountMissing));
    assert_eq!(doors.revoked.lock().unwrap().clone(), vec!["handoff-bob-cookie".to_owned()]);
    assert!(matches!(flow.exchange("never-issued").await.unwrap(), Handoff::Expired));
}

#[test]
fn the_options_say_which_doors_are_open() {
    let options = |sso, password, label: Option<&str>| {
        let (flow, ..) = flow_with(clock(), SignInMethodPolicy::new(sso, password), label.map(str::to_owned));
        flow.options()
    };
    assert_eq!(options(false, true, None), SignInOptions { single_sign_on: false, label: None, password: true });
    assert_eq!(
        options(true, true, Some("Keycloak")),
        SignInOptions { single_sign_on: true, label: Some("Keycloak".into()), password: true }
    );
    assert_eq!(
        options(true, false, None),
        SignInOptions { single_sign_on: true, label: Some("single sign-on".into()), password: false }
    );
}

/// `SignInMethodPolicyTest`, its four cases.
#[test]
fn the_password_door_closes_only_behind_a_provider() {
    let policy = SignInMethodPolicy::new(false, true);
    assert!(policy.password_allowed() && !policy.single_sign_on_available(), "the default: password only");
    let policy = SignInMethodPolicy::new(true, true);
    assert!(policy.password_allowed() && policy.single_sign_on_available(), "a provider does not remove it");
    let policy = SignInMethodPolicy::new(true, false);
    assert!(!policy.password_allowed() && policy.single_sign_on_available(), "closed behind a provider");
    assert!(SignInMethodPolicy::new(false, false).password_allowed(), "without one, closing it is refused");
}

#[tokio::test]
async fn changing_one_s_password_spends_the_sign_in_s_budget() {
    let clock = clock();
    let (flow, store, log, _) = flow(shared(&clock));
    store.add(account(1, "alice", true));
    for _ in 0..MAX_ATTEMPTS_PER_USER {
        let changed =
            flow.change_password(1, None, Some("wrong"), Some("a new password of length"), None, None).await.unwrap();
        assert_eq!(changed, PasswordChange::CurrentPasswordWrong);
    }
    assert_eq!(store.attempts_under(&account_key(1)), MAX_ATTEMPTS_PER_USER, "each wrong one kept as a failure");
    // Half a second later, the wait is truncated to whole seconds as `toSeconds()` truncates it.
    clock.advance(Duration::milliseconds(500));
    let changed =
        flow.change_password(1, None, Some(PASSWORD), Some("a new password of length"), None, None).await.unwrap();
    assert_eq!(changed, PasswordChange::Throttled { retry_after_seconds: 899 });
    assert_eq!(log.last().description, "Password change refused by the throttle (899s to wait)");
    assert_eq!(store.attempts_under(&account_key(1)), MAX_ATTEMPTS_PER_USER, "a refusal takes its row back");

    // And a sign-in's failures are the same counter.
    clock.advance(Duration::minutes(15));
    assert!(matches!(
        flow.change_password(1, None, Some(PASSWORD), Some("a new password of length"), None, None).await.unwrap(),
        PasswordChange::Changed { .. }
    ));
    assert_eq!(store.attempts_under(&account_key(1)), 0, "a right current password clears the account's counter");
}

// ── TotpService ──────────────────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn enrolment_seals_the_secret_and_eight_codes_under_java_s_contexts() {
    let clock = clock();
    let (flow, store, log, _) = flow(shared(&clock));
    store.add(account(3, "carol", true));
    let secret = totp::generate_secret();
    let codes = flow.second_factor().enable(3, &secret, &totp::generate_code(&secret, NOW).unwrap()).await.unwrap();
    assert_eq!(codes.len(), 8);

    let user = store.user(3);
    assert!(user.mfa_enabled);
    assert_eq!(user.totp_secret, Some(Sealed::new(format!("sealed[{}]{secret}", secret_context(3)))));
    let joined = codes.iter().map(|code| code.expose()).collect::<Vec<_>>().join(",");
    assert_eq!(user.mfa_backup_codes, Some(Sealed::new(format!("sealed[{}]{joined}", backup_context(3)))));
    assert_eq!(user.totp_last_step, Some(NOW.unix_timestamp() / 30), "the enrolment's step is spent");
    assert_eq!(user.updated_at, NOW);
    let entry = log.last();
    assert_eq!(entry.operation, AuditOperation::UserUpdated);
    assert_eq!((entry.resource.as_str(), entry.description.as_str()), ("3", "MFA / TOTP enabled for user: carol"));
    assert_eq!((entry.ip_address.as_deref(), entry.user_agent.as_deref()), (None, None));
}

#[tokio::test]
async fn enrolment_refuses_a_wrong_code_and_an_active_factor() {
    let clock = clock();
    let (flow, store, _, _) = flow(shared(&clock));
    store.add(account(3, "carol", true));
    let secret = totp::generate_secret();
    let wrong = flow.second_factor().enable(3, &secret, "000000").await;
    assert!(matches!(wrong, Err(SecondFactorError::InvalidInput(INVALID_ENROLMENT_CODE))), "{wrong:?}");
    assert!(!store.user(3).mfa_enabled);

    flow.second_factor().enable(3, &secret, &totp::generate_code(&secret, NOW).unwrap()).await.unwrap();
    let attacker = totp::generate_secret();
    let over = flow.second_factor().enable(3, &attacker, &totp::generate_code(&attacker, NOW).unwrap()).await;
    assert!(matches!(over, Err(SecondFactorError::InvalidInput(ALREADY_ENABLED))), "{over:?}");
    assert_eq!(
        ALREADY_ENABLED,
        "MFA is already enabled. Disable it with a current code before enrolling a new device."
    );
    assert!(matches!(flow.second_factor().enable(99, &secret, "0").await, Err(SecondFactorError::AccountMissing)));
}

#[tokio::test]
async fn a_code_opens_once_and_the_enrolment_s_code_never() {
    let clock = clock();
    let (flow, store, _, _) = flow(shared(&clock));
    store.add(account(3, "carol", true));
    let secret = totp::generate_secret();
    flow.second_factor().enable(3, &secret, &totp::generate_code(&secret, NOW).unwrap()).await.unwrap();
    let factor = flow.second_factor();

    assert!(!factor.verify(&store.user(3), totp::generate_code(&secret, NOW).as_deref()).await.unwrap(), "spent");
    let next = totp::generate_code(&secret, NOW + Duration::seconds(30)).unwrap();
    assert!(factor.verify(&store.user(3), Some(&format!("  {next}\t"))).await.unwrap(), "trimmed as String.trim");
    assert!(!factor.verify(&store.user(3), Some(&next)).await.unwrap(), "a replay");
}

#[tokio::test]
async fn nothing_opens_a_disabled_factor_and_a_blank_code_opens_nothing() {
    let clock = clock();
    let (flow, store, _, _) = flow(shared(&clock));
    store.add(account(3, "carol", true));
    let secret = totp::generate_secret();
    let codes = flow.second_factor().enable(3, &secret, &totp::generate_code(&secret, NOW).unwrap()).await.unwrap();
    let factor = flow.second_factor();
    for blank in [None, Some(""), Some("   "), Some("\u{2003}")] {
        assert!(!factor.verify(&store.user(3), blank).await.unwrap(), "{blank:?}");
    }
    let mut off = store.user(3);
    off.mfa_enabled = false;
    assert!(!factor.verify(&off, Some(codes[0].expose())).await.unwrap());
}

#[tokio::test]
async fn a_backup_code_is_spent_once_and_audited() {
    let clock = clock();
    let (flow, store, log, _) = flow(shared(&clock));
    store.add(account(3, "carol", true));
    let secret = totp::generate_secret();
    let codes = flow.second_factor().enable(3, &secret, &totp::generate_code(&secret, NOW).unwrap()).await.unwrap();
    let factor = flow.second_factor();
    let (first, second) = (store.user(3), store.user(3));

    clock.advance(Duration::minutes(1));
    assert!(factor.verify(&first, Some(codes[0].expose())).await.unwrap());
    assert!(!factor.verify(&second, Some(codes[0].expose())).await.unwrap(), "the same code through another copy");
    let remaining = codes.iter().skip(1).map(|code| code.expose()).collect::<Vec<_>>().join(",");
    assert_eq!(store.user(3).mfa_backup_codes, Some(Sealed::new(format!("sealed[{}]{remaining}", backup_context(3)))));
    assert_eq!(store.user(3).updated_at, NOW + Duration::minutes(1));
    let entry = log.last();
    assert_eq!(entry.description, "Emergency backup recovery code used by: carol");
    assert_eq!(entry.signal, Some("MFA_BACKUP_CODE_USED"));
    assert_eq!(entry.resource, "3");
    assert!(factor.verify(&store.user(3), Some(codes[1].expose())).await.unwrap(), "the others still there");

    // A spend another sign-in won between the read and the write opens nothing.
    store.state().backup_codes_raced = true;
    assert!(!factor.verify(&store.user(3), Some(codes[2].expose())).await.unwrap());
}

#[tokio::test]
async fn a_secret_under_another_context_reads_as_unreadable() {
    let clock = clock();
    let (flow, store, _, _) = flow(shared(&clock));
    let secret = totp::generate_secret();
    let mut user = account(3, "carol", true);
    user.mfa_enabled = true;
    user.totp_secret = Some(Sealed::new(format!("sealed[{}]{secret}", secret_context(4))));
    user.mfa_backup_codes = Some(Sealed::new(format!("sealed[{}]abcd-efgh", backup_context(4))));
    store.add(user);
    let code = totp::generate_code(&secret, NOW).unwrap();
    assert!(!flow.second_factor().verify(&store.user(3), Some(&code)).await.unwrap());
    assert!(!flow.second_factor().verify(&store.user(3), Some("abcd-efgh")).await.unwrap());
}

#[tokio::test]
async fn disabling_spends_the_same_budget_and_wants_a_right_code() {
    let clock = clock();
    let (flow, store, log, _) = flow(shared(&clock));
    store.add(account(3, "carol", true));
    let secret = totp::generate_secret();
    let codes = flow.second_factor().enable(3, &secret, &totp::generate_code(&secret, NOW).unwrap()).await.unwrap();
    let factor = flow.second_factor();

    let wrong = factor.disable(3, "000000").await;
    assert!(matches!(wrong, Err(SecondFactorError::InvalidInput(INVALID_DISABLE_CODE))), "{wrong:?}");
    assert_eq!(store.attempts_under(&second_factor_key(3)), 1, "the reservation stays: it is this failure");

    store.seed_attempts(&second_factor_key(3), MAX_SECOND_FACTOR_FAILURES - 1, NOW);
    let locked = factor.disable(3, codes[0].expose()).await;
    let Err(SecondFactorError::Locked { retry_after }) = locked else { panic!("{locked:?}") };
    assert_eq!(retry_after, Duration::seconds(890));
    assert_eq!(SecondFactorError::Locked { retry_after }.to_string(), LOCKED);
    assert!(store.user(3).mfa_enabled);

    clock.advance(Duration::minutes(15));
    factor.disable(3, codes[0].expose()).await.unwrap();
    let user = store.user(3);
    assert!(!user.mfa_enabled);
    assert_eq!((user.totp_secret, user.mfa_backup_codes, user.totp_last_step), (None, None, None));
    assert_eq!(store.attempts_under(&second_factor_key(3)), 0, "a right code clears the budget");
    assert_eq!(log.last().description, "MFA / TOTP disabled for user: carol");
}

#[tokio::test]
async fn the_enrolment_counts_are_clamped() {
    let clock = clock();
    let (flow, store, _, _) = flow(shared(&clock));
    store.add(account(1, "a", true));
    let mut enrolled = account(2, "b", true);
    enrolled.mfa_enabled = true;
    store.add(enrolled);
    store.add(account(3, "c", false));
    let mut federated = account(4, "d", true);
    federated.password = None;
    store.add(federated);
    let counts = flow.second_factor().enrolment().await.unwrap();
    assert_eq!((counts.password_accounts, counts.without_second_factor), (2, 1));

    // An account created between the two statements is clamped out rather than reported as "3 of 2".
    store.state().counts_override = Some((2, 3));
    let counts = flow.second_factor().enrolment().await.unwrap();
    assert_eq!((counts.password_accounts, counts.without_second_factor), (2, 2));
}

#[test]
fn setup_names_the_issuer() {
    let (flow, ..) = flow(clock());
    let setup = flow.second_factor().setup("carol smith");
    assert_eq!(setup.issuer, "Vectispire");
    assert!(setup.qr_code_uri.expose().starts_with("otpauth://totp/Vectispire:carol+smith?secret="));
    assert_eq!(totp::decode_base32(setup.secret.expose()).len(), 20);
}

// ── RateWindows ──────────────────────────────────────────────────────────────────────────────────────────────

fn windows(clock: &Arc<HandClock>) -> (RateWindows<Memory>, Memory) {
    let store = Memory::default();
    (RateWindows::new(store.clone(), shared(clock)), store)
}

const MINUTE: std::time::Duration = std::time::Duration::from_secs(60);

#[tokio::test]
async fn a_window_admits_its_ceiling_and_says_when_it_closes() {
    let clock = HandClock::at(NOW + Duration::seconds(20));
    let (windows, store) = windows(&clock);
    let admitted: Vec<bool> = {
        let mut admitted = Vec::new();
        for _ in 0..7 {
            admitted.push(windows.hit(Limit::TicketWebhook, Some("203.0.113.7"), 5, MINUTE).await.admitted);
        }
        admitted
    };
    assert_eq!(admitted, [true, true, true, true, true, false, false]);
    let number = (NOW + Duration::seconds(20)).unix_timestamp() * 1000 / 60_000;
    let key = format!("webhook:{number}:{}", sha256_hex("203.0.113.7"));
    assert_eq!(store.state().windows.get(&key).map(|(hits, _)| *hits), Some(7), "{:?}", store.state().windows);
    assert_eq!(store.state().windows[&key].1, NOW + Duration::minutes(1), "the window closes on its minute");
    let refused = windows.hit(Limit::TicketWebhook, Some("203.0.113.7"), 5, MINUTE).await;
    assert_eq!(refused.retry_after, std::time::Duration::from_secs(40));
    // Another subject has a window of its own; an absent one is the empty string's.
    assert!(windows.hit(Limit::TicketWebhook, None, 5, MINUTE).await.admitted);
    assert!(store.state().windows.contains_key(&format!("webhook:{number}:{}", sha256_hex(""))));
}

fn sha256_hex(text: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(text.as_bytes()).iter().map(|byte| format!("{byte:02x}")).collect()
}

#[tokio::test]
async fn a_window_before_the_epoch_is_floored() {
    let clock = HandClock::at(time::OffsetDateTime::UNIX_EPOCH - Duration::milliseconds(1));
    let (windows, store) = windows(&clock);
    windows.hit(Limit::TicketWebhook, Some("x"), 5, MINUTE).await;
    assert!(store.state().windows.keys().all(|key| key.starts_with("webhook:-1:")), "{:?}", store.state().windows);
}

#[tokio::test]
async fn a_first_hit_that_loses_the_insert_is_counted_not_lost() {
    let clock = clock();
    let (windows, store) = windows(&clock);
    store.state().lose_first_insert = true;
    assert!(windows.hit(Limit::TicketWebhook, Some("x"), 5, MINUTE).await.admitted);
    assert_eq!(store.state().windows.values().next().unwrap().0, 2, "the other instance's hit and this one");
}

#[tokio::test]
async fn a_database_that_does_not_answer_admits() {
    let clock = clock();
    let (windows, store) = windows(&clock);
    store.state().failing = true;
    let outcome = windows.hit(Limit::TicketWebhook, Some("x"), 0, MINUTE).await;
    assert!(outcome.admitted && outcome.retry_after.is_zero());
}

#[tokio::test]
async fn the_purge_takes_closed_windows_and_forget_takes_a_limit() {
    let clock = clock();
    let (windows, store) = windows(&clock);
    windows.hit(Limit::TicketWebhook, Some("x"), 5, MINUTE).await;
    store.state().windows.insert("webhook:0:stale".into(), (3, NOW - Duration::hours(1)));
    assert_eq!(windows.purge_closed().await.unwrap(), 1);
    assert_eq!(store.state().windows.len(), 1);
    assert_eq!(windows.forget(Limit::TicketWebhook).await.unwrap(), 1);
}

// ── SessionCleanupService ────────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_cleanup_purges_four_tables_and_keeps_attempts_twice_the_window() {
    let clock = clock();
    let store = Memory::default();
    assert_eq!(ATTEMPT_RETENTION, Duration::minutes(30));
    store.seed_attempts("old", 1, NOW - Duration::minutes(30));
    store.seed_attempts("kept", 1, NOW - Duration::minutes(29));
    store.state().windows.insert("webhook:0:stale".into(), (3, NOW - Duration::seconds(1)));
    let cleanup = SessionCleanup::new(Doors::default(), store.clone(), store.clone(), shared(&clock));
    let result = cleanup.prune().await;
    assert_eq!(result, CleanupResult { sessions: 2, attempts: 1, challenges: 0, rate_windows: 1 });
    assert_eq!(store.attempts_under("kept"), 1);
}

#[tokio::test]
async fn the_cleanup_never_fails_the_tick() {
    let clock = clock();
    let store = Memory::default();
    store.state().failing = true;
    let doors = Doors { failing_purge: true, ..Doors::default() };
    let task = SessionCleanupTask(SessionCleanup::new(doors, store.clone(), store, shared(&clock)));
    assert_eq!(task.sequence(), Sequence::SessionCleanup);
    assert!(task.run().await.is_ok());

    // One purge failing does not stop the others.
    let store = Memory::default();
    store.state().windows.insert("webhook:0:stale".into(), (3, NOW - Duration::seconds(1)));
    let doors = Doors { failing_purge: true, ..Doors::default() };
    let result = SessionCleanup::new(doors, store.clone(), store, shared(&clock)).prune().await;
    assert_eq!(result, CleanupResult { sessions: 0, attempts: 0, challenges: 0, rate_windows: 1 });
}

// ── the throttle alone ───────────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_reservation_counts_others_rows_and_never_its_own() {
    let clock = clock();
    let store = Memory::default();
    let throttle = Throttle::new(store.clone(), shared(&clock));
    store.seed_attempts("k", 4, NOW);
    let admitted = throttle.reserve(&[("k".into(), 5)]).await.unwrap();
    assert!(admitted.admitted(), "four others and itself: the fifth is admitted");
    assert_eq!(admitted.rows.len(), 1);
    let refused = throttle.reserve(&[("k".into(), 5)]).await.unwrap();
    assert!(!refused.admitted());
    assert_eq!(store.attempts_under("k"), 5, "the refused one took its row back");

    // Outside the window, a failure is not counted; at its edge, it has left.
    clock.advance(Duration::minutes(15) - Duration::seconds(10));
    assert!(throttle.reserve(&[("k".into(), 5)]).await.unwrap().admitted());
}

#[tokio::test]
async fn the_strictest_ceiling_wins_whatever_its_place() {
    let clock = clock();
    let store = Memory::default();
    let throttle = Throttle::new(store.clone(), shared(&clock));
    {
        let mut state = store.state();
        for _ in 0..5 {
            state.attempts.push((uuid::Uuid::new_v4(), "short".into(), NOW - Duration::seconds(800)));
            state.attempts.push((uuid::Uuid::new_v4(), "long".into(), NOW - Duration::seconds(10)));
        }
    }
    let refused = throttle.reserve(&[("short".into(), 5), ("long".into(), 5)]).await.unwrap();
    assert_eq!(refused.retry_after, Duration::seconds(890));
    let refused = throttle.reserve(&[("long".into(), 5), ("short".into(), 5)]).await.unwrap();
    assert_eq!(refused.retry_after, Duration::seconds(890));
}
