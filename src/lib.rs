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
//! use tinyminiscript::parse_script;
//!
//! // Parse a simple miniscript
//! let result = parse_script("wsh(multi(1,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc))");
//! if let Ok((ctx, script)) = result {
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
#![forbid(unsafe_code)]

#[cfg(feature = "debug")]
/// AST printer
mod ast_printer;
/// Bitcoin descriptor parsing and validation
pub mod descriptor;
/// Limits for miniscript expressions
pub mod limits;
/// Miniscript parser and AST representation
pub mod parser;

mod macros;

/// Satisfactions and dis-satisfactions of miniscript expressions
pub mod satisfy;
/// Bitcoin script generation from parsed miniscript
pub mod script;
/// Type checking and correctness property validation
pub mod type_checker;

pub extern crate alloc;
pub(crate) type Vec<T> = alloc::vec::Vec<T>;

// ---

use bitcoin::ScriptBuf;
use parser::ASTVisitor;

use parser::ParserContext;
use type_checker::TypeInfo;

/// Errors that can occur during miniscript parsing, validation, or script building.
///
/// When the `debug` feature is enabled, this enum implements [`Debug`] for easier
/// debugging and error reporting in development environments.
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum MiniscriptError<'a> {
    /// Error occurred during parsing of the miniscript string
    ParserError(parser::ParseError<'a>),
    /// Error occurred during type checking and correctness validation
    TypeCheckerError(type_checker::CorrectnessPropertiesVisitorError),
    /// Error occurred during descriptor validation
    DescriptorVisitorError(descriptor::DescriptorVisitorError),
    /// Error occurred during Bitcoin script generation
    ScriptBuilderError(script::ScriptBuilderError<'a>),
    /// Error occurred during script size checking
    LimitsError(limits::LimitsError),
}

/// Parse and validate a miniscript string, returning the parsed context and generated Bitcoin script.
///
/// This function performs a complete validation pipeline:
/// 1. Parses the miniscript string into an AST
/// 2. Type checks the AST for correctness properties
/// 3. Validates the descriptor structure
/// 4. Generates the corresponding Bitcoin script
///
/// # Arguments
///
/// * `script` - The miniscript string to parse and validate
///
/// # Returns
///
/// Returns `Ok((ParserContext, ScriptBuf))` on success, where:
/// - [`ParserContext`] contains the parsed AST and metadata
/// - [`ScriptBuf`] is the generated Bitcoin script
///
/// Returns `Err(MiniscriptError)` if parsing, validation, or script generation fails.
///
/// # Examples
///
/// ```rust
/// use tinyminiscript::parse_script;
///
/// let result = parse_script("pk(02e79c4c8b3c8b3c8b3c8b3c8b3c8b3c8b3c8b3c8b3c8b3c8b3c8b3c8b3c8b3)");
/// match result {
///     Ok((ctx, script)) => println!("Generated script: {:?}", script),
///     Err(e) => eprintln!("Parse error: {:?}", e),
/// }
/// ```
pub fn parse_script<'a>(
    script: &'a str,
) -> Result<(ParserContext<'a>, ScriptBuf), MiniscriptError<'a>> {
    let ctx = parser::parse(script).map_err(MiniscriptError::ParserError)?;

    // Type check the AST for correctness properties
    let type_info: TypeInfo = type_checker::CorrectnessPropertiesVisitor::new()
        .visit(&ctx)
        .map_err(MiniscriptError::TypeCheckerError)?;

    // Validate the descriptor structure
    let _: () = descriptor::DescriptorValidator::new()
        .visit(&ctx)
        .map_err(MiniscriptError::DescriptorVisitorError)?;

    // Check the recursion depth
    limits::check_recursion_depth(type_info.tree_height).map_err(MiniscriptError::LimitsError)?;

    // Check the script size
    limits::check_script_size(
        &ctx.top_level_descriptor
            .clone()
            .expect("Top level descriptor must be set"),
        type_info.pk_cost,
    )
    .map_err(MiniscriptError::LimitsError)?;

    // Generate the Bitcoin script
    let script_buf = script::build_script(&ctx).map_err(MiniscriptError::ScriptBuilderError)?;

    Ok((ctx, script_buf))
}
