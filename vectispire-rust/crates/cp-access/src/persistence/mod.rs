//! The access module's rows: `t_user` here; `t_session` and `t_api_key` are the credentials task's, reached
//! through [`SessionsAndKeys`] inside the same transaction.

pub(crate) mod model;
pub(crate) mod users;

pub use model::{AccountStore, NewUser, PasswordHash, RevokedKey, Sealed, SessionHash, StoreError, User};
pub use users::{SessionsAndKeys, SqlAccountStore};
