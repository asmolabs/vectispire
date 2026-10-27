//! Persistence layer for the inventory crate.

pub mod repository;
#[cfg(test)]
mod tests;

pub use repository::*;
