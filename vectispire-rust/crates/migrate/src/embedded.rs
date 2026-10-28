//! The files `build.rs` embedded: `vectispire-core`'s `db/migration`, byte for byte.

include!(concat!(env!("OUT_DIR"), "/embedded.rs"));
