//! The Wasmtime command line interface (CLI) crate.
//!
//! This crate implements the Wasmtime command line tools.

#![deny(missing_docs)]

pub mod commands;
pub mod audit;

#[cfg(feature = "run")]
pub(crate) mod common;
