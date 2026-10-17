//! Who is calling, as the chain sees them: a role, a credential kind, and what the credential may reach.
//!
//! The lookups behind it — a session's hash in the table, an API key's prefix and hash, the SCIM token — are
//! Phase 1's (`cp-access`). This crate decides what a principal *may reach*, and takes the principal from a
//! [`Credentials`](crate::credentials::Credentials) it is handed.

/// `Role` and its flags, as the Java enum spells them.
///
/// **The one `Role` of the control plane**: the chain reads it here, `cp-access` adds the six flags as a table
/// (`roles::RoleFlags`), and the accounts' rules read both. The variants are in the Java enum's declaration order,
/// which the derived `Ord` and [`Role::ALL`] follow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Role {
    Superuser,
    Admin,
    Ciso,
    SecurityChampion,
    Auditor,
    User,
}

impl Role {
    /// Every role, in the Java enum's declaration order — `Role.values()`.
    pub const ALL: [Role; 6] =
        [Role::Superuser, Role::Admin, Role::Ciso, Role::SecurityChampion, Role::Auditor, Role::User];

    /// The name stored in `t_user.role`, sent on the wire and named in a `hasAnyRole` expression.
    pub const fn name(self) -> &'static str {
        match self {
            Role::Superuser => "SUPERUSER",
            Role::Admin => "ADMIN",
            Role::Ciso => "CISO",
            Role::SecurityChampion => "SECURITY_CHAMPION",
            Role::Auditor => "AUDITOR",
            Role::User => "USER",
        }
    }

    /// `Role.of`: the exact name, case included; anything else — `admin` for `ADMIN` too — is no role. An
    /// unreadable stored role authorizes nothing; it is never read as the least privileged one.
    pub fn of(value: Option<&str>) -> Option<Role> {
        value.and_then(Role::parse)
    }

    /// `Role.administrative()`: the administrative roles, in declaration order — derived, never listed again.
    pub fn administrative() -> Vec<Role> {
        Role::ALL.into_iter().filter(|role| role.is_administrative()).collect()
    }

    pub fn parse(value: &str) -> Option<Role> {
        Some(match value {
            "SUPERUSER" => Role::Superuser,
            "ADMIN" => Role::Admin,
            "CISO" => Role::Ciso,
            "SECURITY_CHAMPION" => Role::SecurityChampion,
            "AUDITOR" => Role::Auditor,
            "USER" => Role::User,
            _ => return None,
        })
    }

    /// `Role.isAdministrative()`: the two roles that administer accounts.
    pub fn is_administrative(self) -> bool {
        matches!(self, Role::Superuser | Role::Admin)
    }

    /// `Role.canCauseEffects()`: may start a scan, answer a checklist, change what a project holds.
    pub fn can_cause_effects(self) -> bool {
        matches!(self, Role::Admin | Role::Ciso | Role::SecurityChampion | Role::User)
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.name())
    }
}

/// An API key's scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ApiKeyScope {
    Read,
    Scan,
    Export,
    SarifImport,
    ReportImport,
    Agent,
}

impl ApiKeyScope {
    pub fn wire_name(self) -> &'static str {
        match self {
            ApiKeyScope::Read => "read",
            ApiKeyScope::Scan => "scan",
            ApiKeyScope::Export => "export",
            ApiKeyScope::SarifImport => "sarif_import",
            ApiKeyScope::ReportImport => "report_import",
            ApiKeyScope::Agent => "agent",
        }
    }
}

/// An account behind a session or an integration key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub username: String,
    /// `None` when the stored role is unreadable: such an account is authorized for nothing, **not** for the
    /// least privileged role, which would keep a mistyped account working with nobody ever looking.
    pub role: Option<Role>,
    pub must_change_password: bool,
}

/// The credential a request authenticated with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Credential {
    /// A session — a browser's or a script's bearer token.
    Session,
    /// An integration API key: its id (the budget is per key) and its scopes.
    Integration { key_id: String, scopes: Vec<ApiKeyScope> },
    /// An agent's key.
    Agent { agent: String },
    /// The identity provider's SCIM token, a principal on `/scim` and nowhere else.
    Scim,
}

/// What a credential may see on its own, before its account's grants: an integration key issued for one target is
/// narrowed to it (decision 0024) — `VectispirePrincipal.credentialRestriction()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Restriction {
    /// A session, an agent, the SCIM client, an unrestricted key.
    #[default]
    None,
    /// A key issued for this target.
    Target(vectispire_domain::ScanTarget),
    /// A key restricted to a kind nobody wrote: it sees nothing, never everything.
    Nothing,
}

/// What the credentials module knew of the caller when it resolved them, beyond what the chain itself reads: the
/// account's row id and stored role — what the visibility is resolved for — the credential's own restriction, and the
/// name an audit entry is attributed to. **The restriction travels with the principal** so that every scoped route
/// intersects the account's visibility with it; a principal that lost it would read with its account's whole estate.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Grounds {
    pub account_id: Option<i64>,
    /// The role as stored, unparsed: an unreadable role is no global scope, never the least privileged one.
    pub stored_role: Option<String>,
    pub restriction: Restriction,
    /// `RequestActors.of`: the username, or `user (key name)` for an integration key.
    pub actor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    /// Absent for an agent and for the SCIM client.
    pub account: Option<Account>,
    pub credential: Credential,
    /// Empty for a principal built by a test double that does not say more.
    pub grounds: Grounds,
}

impl Principal {
    pub fn session(account: Account) -> Principal {
        Principal { account: Some(account), credential: Credential::Session, grounds: Grounds::default() }
    }

    pub fn integration(account: Account, key_id: &str, scopes: Vec<ApiKeyScope>) -> Principal {
        Principal {
            account: Some(account),
            credential: Credential::Integration { key_id: key_id.to_owned(), scopes },
            grounds: Grounds::default(),
        }
    }

    pub fn agent(agent: &str) -> Principal {
        Principal {
            account: None,
            credential: Credential::Agent { agent: agent.to_owned() },
            grounds: Grounds::default(),
        }
    }

    /// The SCIM client acts as an administrator on `/scim`: its authorities are `ROLE_ADMIN` and `SCOPE_SCIM`.
    pub fn scim() -> Principal {
        Principal { account: None, credential: Credential::Scim, grounds: Grounds::default() }
    }

    /// The roles the principal's authorities carry.
    pub fn role(&self) -> Option<Role> {
        match &self.credential {
            Credential::Scim => Some(Role::Admin),
            Credential::Agent { .. } => None,
            _ => self.account.as_ref().and_then(|account| account.role),
        }
    }

    /// The same principal, with what its credential's resolution knew.
    pub fn with_grounds(mut self, grounds: Grounds) -> Principal {
        self.grounds = grounds;
        self
    }

    /// The name an audit entry is attributed to: what the resolution said, else the account's username.
    pub fn actor(&self) -> Option<String> {
        self.grounds.actor.clone().or_else(|| self.account.as_ref().map(|account| account.username.clone()))
    }

    pub fn must_change_password(&self) -> bool {
        self.account.as_ref().is_some_and(|account| account.must_change_password)
    }

    pub fn is_session(&self) -> bool {
        matches!(self.credential, Credential::Session)
    }

    pub fn is_agent(&self) -> bool {
        matches!(self.credential, Credential::Agent { .. })
    }
}
