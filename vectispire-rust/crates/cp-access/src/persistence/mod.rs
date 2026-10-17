//! Every statement the module runs — the grants and the approver count. Nothing above this names a query API: a
//! service hands a criterion down and gets rows, or a [`StoreError`], back.

pub(crate) mod accounts;
pub(crate) mod grants;

/// A statement the database refused or could not answer. The driver's error stays inside, as the cause.
#[derive(Debug, thiserror::Error)]
#[error("the database did not answer: {0}")]
pub struct StoreError(#[from] sqlx::Error);
