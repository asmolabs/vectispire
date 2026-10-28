//! The database these tests run on: `vectispire_cp_db::testing`'s — one of its own for each test, migrated by
//! `vectispire-migrate`, in a throwaway container or on the shared server `VECTISPIRE_TEST_MYSQL_URL` /
//! `VECTISPIRE_TEST_POSTGRES_URL` names (see that module).

#[allow(unused_imports)] // not every suite of the crate reaches a database
pub use vectispire_cp_db::testing::TestDatabase as Migrated;
