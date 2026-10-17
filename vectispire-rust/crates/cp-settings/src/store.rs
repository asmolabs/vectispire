//! The settings, as text keyed by name — `SettingsService`.
//!
//! **The catalog is the domain's, the storage is this table's.** A row whose key is not in [`Setting`] is not an
//! error: it is a setting that has been removed, and the reader that no longer asks for it never sees it. **Reads
//! go through [`Setting`], and the default comes from the catalog**: one definition, next to the label and the
//! help that describe it, where call sites with their own fallbacks drifted.

use std::collections::BTreeMap;

use vectispire_cp_db::{Db, Tx};

use crate::catalog::Setting;
use crate::persistence::{self, DbError};
use crate::types::parse_int;

/// Why a write was refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    /// A catalog key through the door for the deployment's own rows: that row has a label, a validation and an
    /// audit trail, which this door would skip.
    #[error("{0}")]
    CatalogKey(String),
    #[error(transparent)]
    Database(#[from] DbError),
}

/// The settings store.
#[derive(Debug, Clone)]
pub struct Settings {
    db: Db,
}

impl Settings {
    pub fn new(db: Db) -> Settings {
        Settings { db }
    }

    /// Every stored value, with no default filled in — what is on disk, not what applies. A row without a value
    /// reads as empty.
    pub async fn stored(&self) -> Result<BTreeMap<String, String>, SettingsError> {
        Ok(persistence::all(&self.db).await?.into_iter().map(|(key, value)| (key, value.unwrap_or_default())).collect())
    }

    /// Every setting in the catalog with its effective value: stored if present, default if not — and the rows of
    /// removed or internal keys, as Java's map holds them.
    pub async fn effective(&self) -> Result<BTreeMap<String, String>, SettingsError> {
        let mut values: BTreeMap<String, String> =
            Setting::defaults().into_iter().map(|(key, value)| (key.to_owned(), value.to_owned())).collect();
        values.extend(self.stored().await?);
        Ok(values)
    }

    /// The value that applies. **The stored value wins even when empty**: an operator who cleared a field means
    /// it, and substituting the default there is how a cleared webhook URL comes back to life.
    pub async fn get(&self, setting: Setting) -> Result<String, SettingsError> {
        Ok(match persistence::find(&self.db, setting.key()).await? {
            Some(value) => value.unwrap_or_default(),
            None => setting.default_value().to_owned(),
        })
    }

    /// Whether the key has a row of its own — not the same question as [`Settings::get`] returning the default: an
    /// operator may have written the value the catalog also proposes, and overwriting it overwrites a decision.
    pub async fn is_stored(&self, setting: Setting) -> Result<bool, SettingsError> {
        Ok(persistence::find(&self.db, setting.key()).await?.is_some())
    }

    /// A boolean setting: anything that is not `true` is false, the absent row included.
    pub async fn is_enabled(&self, setting: Setting) -> Result<bool, SettingsError> {
        Ok(self.get(setting).await? == "true")
    }

    /// An integer setting. A row written before a validation rule tightened must not take a screen down: an
    /// unreadable value is the catalog's default, the answer the deployment would give with no row at all.
    pub async fn as_int(&self, setting: Setting) -> Result<i32, SettingsError> {
        let value = self.get(setting).await?;
        // Every integer default parses: the catalog's reference test holds the catalog to it.
        Ok(parse_int(&value).or_else(|| parse_int(setting.default_value())).unwrap_or_default())
    }

    /// A row no [`Setting`] names — a value the deployment keeps for itself and never shows on the settings
    /// screen, such as the encrypted document signing key. `None` when absent, and when the row holds no value.
    ///
    /// **Outside any caller's transaction, deliberately**: this is the read-back of a row
    /// [`Settings::store_internal_if_absent`] has just committed, which a caller's `REPEATABLE READ` snapshot
    /// (MySQL's default) taken before it would not show.
    pub async fn internal_value(&self, key: &str) -> Result<Option<String>, SettingsError> {
        Ok(persistence::find(&self.db, key).await?.flatten())
    }

    /// Stores such a row unless one exists, and says whether it did — `false` when the key already had a row,
    /// which is left as it was.
    ///
    /// **Insert-if-absent, never overwrite.** This was a merge once, and two instances starting together each
    /// generated a signing key and each read back its own: the second write replaced the first after the first
    /// instance had already signed with it. The insert fails for whoever comes second, and the caller reads back
    /// the row that won. **Outside the caller's transaction**, which may be read-only — documents are signed in
    /// read-only transactions, the evidence bundle's among them.
    ///
    /// Decided by what is there, not by the error's type: a lock timeout or a dropped connection fails the
    /// insert too, and a refusal with no row behind it is some other failure, returned.
    pub async fn store_internal_if_absent(&self, key: &str, value: &str) -> Result<bool, SettingsError> {
        match persistence::insert(&self.db, key, Some(value)).await {
            Ok(rows) => Ok(rows == 1),
            Err(refused) => {
                if persistence::find(&self.db, key).await?.is_some() {
                    Ok(false)
                } else {
                    Err(SettingsError::Database(refused))
                }
            }
        }
    }

    /// Writes a row no [`Setting`] names, creating it if absent, in the caller's transaction — refused for a
    /// catalog key.
    pub async fn set_internal(&self, tx: &mut Tx, key: &str, value: &str) -> Result<(), SettingsError> {
        refuse_catalog_key(key, "written through set(Setting, …)")?;
        if persistence::update_value(tx, key, Some(value)).await? == 0 {
            persistence::insert_in(tx, key, Some(value)).await?;
        }
        Ok(())
    }

    /// Moves a row no [`Setting`] names from the value its caller read to another, **in the caller's
    /// transaction**, and says whether this caller is the one that moved it — for state that must change once,
    /// whoever else is looking, with an effect that commits with the change or not at all. The row must exist:
    /// an update cannot arbitrate over a row nobody has written.
    pub async fn replace_internal(
        &self,
        tx: &mut Tx,
        key: &str,
        expected: &str,
        value: &str,
    ) -> Result<bool, SettingsError> {
        refuse_catalog_key(key, "written through set(Setting, …)")?;
        Ok(persistence::replace_value(tx, key, expected, value).await? == 1)
    }

    /// Deletes a row no [`Setting`] names: the state kept for something that no longer exists.
    pub async fn remove_internal(&self, tx: &mut Tx, key: &str) -> Result<(), SettingsError> {
        refuse_catalog_key(key, "and is not deleted")?;
        persistence::delete(tx, key).await?;
        Ok(())
    }

    /// Writes a value, creating the row if absent, in the caller's transaction. **Update first, insert only if
    /// nothing was updated**: read-then-write would let two writers of one key both decide to insert. The
    /// residual race — both find nothing, both insert — is left to raise, as Java leaves it: settings are written
    /// from an administration screen at human speed.
    pub async fn set(&self, tx: &mut Tx, setting: Setting, value: &str) -> Result<(), SettingsError> {
        if persistence::update_value(tx, setting.key(), Some(value)).await? == 0 {
            persistence::insert_in(tx, setting.key(), Some(value)).await?;
        }
        Ok(())
    }
}

fn refuse_catalog_key(key: &str, how: &str) -> Result<(), SettingsError> {
    match Setting::by_key(key) {
        Some(_) => Err(SettingsError::CatalogKey(format!("{key} is a catalog setting, {how}."))),
        None => Ok(()),
    }
}
