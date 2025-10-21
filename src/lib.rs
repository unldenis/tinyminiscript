//! A lightweight, `no_std`-compatible miniscript parser and validator for Bitcoin.
//!
//! This crate provides parsing, validation, and script generation for Bitcoin miniscript
//! expressions. It's designed to work in both standard and embedded environments through
//! feature flags.
//!
//! # Features
//!
//! - **`debug`**: Enables `Debug` trait implementations for error types, useful for
//!   development and debugging.
//!
//! # Examples
//!
//! ```rust
//! use tinyminiscript::Context;
//!
//! // Parse a simple miniscript
//! let result = Context::try_from("wsh(multi(1,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc))");
//! if let Ok(ctx) = result {
//!     let script = ctx.build_script().unwrap();
//!     println!("Successfully parsed miniscript");
//!     println!("Generated script: {:?}", script);
//! }
//! ```
//!
//! # Crate Features
//!
//! By default, this crate is `no_std` compatible. Enable the `debug` feature for
//! enhanced error reporting capabilities.

#![cfg_attr(not(test), no_std)]

/// Context for miniscript expressions
pub mod context;
/// Bitcoin descriptor parsing and validation
pub mod descriptor;
/// Limits for miniscript expressions
pub mod limits;
/// Miniscript parser and AST representation
pub mod parser;
/// Satisfactions and dis-satisfactions of miniscript expressions
#[cfg(feature = "satisfy")]
pub mod satisfy;
/// Bitcoin script generation from parsed miniscript
pub mod script;
/// Type checking and correctness property validation
pub mod type_checker;
/// Utility functions
mod utils;

pub extern crate alloc;
pub(crate) type Vec<T> = alloc::vec::Vec<T>;

pub use context::Context;
