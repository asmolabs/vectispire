//! Persistence layer for the inventory crate.

mod entities;
pub mod repository;
#[cfg(test)]
mod tests;

pub use repository::*;
