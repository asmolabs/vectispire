//! The accounts another module names — `AccountNames` (by the name a document may print) and `AccountDirectory` (the
//! checklist contacts' list and reminders, decision 0044).
//!
//! **A display name, never an e-mail address nor a user name** (decision 0035, answer 3). Signed in through an identity
//! provider, a user name is often the person's address, which a document leaving the platform must not carry; and a
//! display name that turns out to be an address — the provider filled it with one, or the person typed theirs — is
//! not printed either: the document then names the account by id.

use std::collections::HashMap;

use vectispire_domain::java;

use crate::account_rules::java_equals_ignore_case;
use crate::accounts::{AccountStore, StoreError, User, UserView};

/// An account as a document names it. `display_name` is `None` where the account has none it may print: its user name
/// is not offered in its place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Named {
    pub account_id: i64,
    pub display_name: Option<String>,
}

/// `AccountNames`.
#[derive(Debug, Clone)]
pub struct AccountNames<S> {
    users: S,
}

impl<S: AccountStore + Sync> AccountNames<S> {
    pub fn new(users: S) -> AccountNames<S> {
        AccountNames { users }
    }

    /// `byUsername`: the accounts these user names belong to now, keyed by the user name **as stored**. A name no
    /// account holds any more is absent from the answer — the document then names nobody rather than print what the
    /// row kept. Each name is looked up as the sign-in looks one up, under the engine's collation, as Java's
    /// `findByUsernameIn` compares — one lookup per distinct name rather than a thousand per statement.
    pub async fn by_username(&self, usernames: &[Option<String>]) -> Result<HashMap<String, Named>, StoreError> {
        let mut distinct: Vec<&str> = Vec::new();
        for name in usernames.iter().flatten() {
            if !distinct.contains(&name.as_str()) {
                distinct.push(name);
            }
        }
        let mut named = HashMap::new();
        for name in distinct {
            if let Some(user) = self.users.find_by_username(name).await? {
                named.insert(user.username.clone(), named_of(&user));
            }
        }
        Ok(named)
    }

    /// `byId`: an account by its id as a document names it; `None` for an id no account holds.
    pub async fn by_id(&self, account_id: i64) -> Result<Option<Named>, StoreError> {
        Ok(self.users.find_by_id(account_id).await?.as_ref().map(named_of))
    }
}

/// `AccountNames.displayNameOf`: an account's display name under the same rule, for a screen or a message naming
/// somebody to people other than the account itself.
pub fn display_name_of(user: &UserView) -> Option<String> {
    printable(user.display_name.as_deref(), user.email.as_deref())
}

/// `AccountDirectory`: the accounts another module asks after — a view, never the row.
#[derive(Debug, Clone)]
pub struct AccountDirectory<S> {
    users: S,
}

impl<S: AccountStore + Sync> AccountDirectory<S> {
    pub fn new(users: S) -> AccountDirectory<S> {
        AccountDirectory { users }
    }

    /// `active`: every active account, by user name.
    pub async fn active(&self) -> Result<Vec<UserView>, StoreError> {
        Ok(self.users.all_by_username().await?.iter().filter(|user| user.is_active).map(UserView::of).collect())
    }

    /// `byId`: an account by its id, active or not; `None` for an id no account holds any more.
    pub async fn by_id(&self, account_id: i64) -> Result<Option<UserView>, StoreError> {
        Ok(self.users.find_by_id(account_id).await?.as_ref().map(UserView::of))
    }
}

fn named_of(user: &User) -> Named {
    Named { account_id: user.id, display_name: printable(user.display_name.as_deref(), user.email.as_deref()) }
}

/// `printable`: `None` for a blank name (`isBlank`), otherwise the name `strip()`ped — unless it holds anything
/// shaped like an address, or is the account's own address whatever its case.
fn printable(stored: Option<&str>, email: Option<&str>) -> Option<String> {
    let stored = stored.filter(|name| !java::is_blank(name))?;
    let name = java::strip(stored);
    let address =
        holds_address(name) || email.is_some_and(|email| java_equals_ignore_case(name, Some(java::strip(email))));
    (!address).then(|| name.to_owned())
}

/// `[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+` found anywhere: an `@` with a character of the class before it, and after it a
/// run of the class holding a `.` that is neither its first nor its last character. `\s` is Java's default class —
/// space, tab, the line feed, vertical tab, form feed and carriage return — not Unicode's whitespace.
fn holds_address(name: &str) -> bool {
    let in_class = |c: char| !matches!(c, ' ' | '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | '@' | '<' | '>');
    let chars: Vec<char> = name.chars().collect();
    chars.iter().enumerate().any(|(at, &c)| {
        if c != '@' || at == 0 || !chars.get(at.wrapping_sub(1)).copied().is_some_and(in_class) {
            return false;
        }
        let run: Vec<char> = chars.iter().skip(at.saturating_add(1)).copied().take_while(|&c| in_class(c)).collect();
        run.iter().enumerate().any(|(dot, &c)| c == '.' && dot > 0 && dot.saturating_add(1) < run.len())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_address_anywhere_in_the_name_is_not_printed() {
        assert_eq!(printable(Some("Ada Lovelace"), None).as_deref(), Some("Ada Lovelace"));
        assert_eq!(printable(Some("  Ada  "), None).as_deref(), Some("Ada"));
        assert_eq!(printable(Some("ada@example.org"), None), None);
        assert_eq!(printable(Some("Ada <ada@example.org>"), None), None);
        assert_eq!(printable(Some("a@b.c"), None), None);
        // Not an address: no dot after the `@`, a dot at either edge of the domain, nothing before the `@`.
        assert_eq!(printable(Some("ada@example"), None).as_deref(), Some("ada@example"));
        assert_eq!(printable(Some("ada@.org"), None).as_deref(), Some("ada@.org"));
        assert_eq!(printable(Some("ada@org."), None).as_deref(), Some("ada@org."));
        assert_eq!(printable(Some("@example.org"), None).as_deref(), Some("@example.org"));
        assert_eq!(printable(Some("x @example.org"), None).as_deref(), Some("x @example.org"));
        // A second `@` ends the run: `a@b@c.d` holds `b@c.d`.
        assert_eq!(printable(Some("a@b@c.d"), None), None);
        // Java's `\s` is ASCII: a no-break space is part of the class.
        assert_eq!(printable(Some("a\u{a0}@b.c"), None), None);
    }

    #[test]
    fn the_account_s_own_address_whatever_its_case_is_not_printed() {
        assert_eq!(printable(Some("ADA"), Some(" ada ")), None);
        assert_eq!(printable(Some("Ada"), Some("bob")).as_deref(), Some("Ada"));
    }

    #[test]
    fn a_blank_name_is_none() {
        assert_eq!(printable(None, None), None);
        assert_eq!(printable(Some(""), None), None);
        assert_eq!(printable(Some(" \u{2003} "), None), None);
    }
}
