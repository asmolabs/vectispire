-- The clients each account has signed in from, for the account's sign-in budget across every client
-- (`LoginThrottle`, `AuthService#login`).
--
-- That budget used to be a hard ceiling: fifty failures a quarter of an hour, from anywhere, and the
-- owner's right password was refused with the guesser's. It is now a soft one, and it does not refuse a
-- client that has already signed in to the account — which is what this table remembers. One row per
-- account and client bucket (the address, or its /64 in IPv6), keyed by the digest of the two so the
-- address itself is not stored here; `last_signed_in_at` is refreshed on every sign-in and a row older
-- than the retention setting is purged by the authentication tables' cleanup.
--
-- In the database and not in memory, as the failure counters are: a restart that forgot every known
-- client would lock every owner out of an account under attack until they waited out the window.
--
-- Written once, in common: a new table, no foreign key (an account's rows go when they age out, and a
-- deleted account's rows open nothing — the key names an id no new account is given).
create table t_sign_in_client (
    client_key varchar(64) not null primary key,
    account_id bigint not null,
    last_signed_in_at ${ts} not null
);

create index idx_sign_in_client_seen on t_sign_in_client (last_signed_in_at);
