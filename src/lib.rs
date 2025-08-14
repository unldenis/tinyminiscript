#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod descriptor;
pub mod parser;
pub mod script;
pub mod type_checker;

// Vec16 and Vec256 are used to store the AST nodes and tokens.
// 'alloc' feature is used to enable the use of alloc::vec::Vec, otherwise
// arrayvec::ArrayVec is used.

#[cfg(feature = "alloc")]
pub extern crate alloc;

#[cfg(feature = "alloc")]
pub(crate) type Vec16<T> = alloc::vec::Vec<T>;
#[cfg(not(feature = "alloc"))]
pub(crate) type Vec16<T> = arrayvec::ArrayVec<T, 16>;

#[cfg(feature = "alloc")]
pub(crate) type Vec256<T> = alloc::vec::Vec<T>;
#[cfg(not(feature = "alloc"))]
pub(crate) type Vec256<T> = arrayvec::ArrayVec<T, 256>;

// ---

use bitcoin::ScriptBuf;
use parser::ASTVisitor;

use crate::{parser::ParserContext, type_checker::TypeInfo};

#[cfg_attr(feature = "debug", derive(Debug))]
pub enum MiniscriptError<'a> {
    ParserError(parser::ParseError<'a>),
    TypeCheckerError(type_checker::CorrectnessPropertiesVisitorError),
    DescriptorVisitorError(descriptor::DescriptorVisitorError),
    ScriptBuilderError(script::ScriptBuilderError<'a>),
}

pub fn parse_script<'a>(
    script: &'a str,
) -> Result<(ParserContext<'a>, ScriptBuf), MiniscriptError<'a>> {
    let ctx = parser::parse(script).map_err(|e| MiniscriptError::ParserError(e))?;

    // type check the ast
    let _: TypeInfo = type_checker::CorrectnessPropertiesVisitor::new()
        .visit(&ctx)
        .map_err(|e| MiniscriptError::TypeCheckerError(e))?;

    // descriptor visitor
    let _: () = descriptor::DescriptorValidator::new()
        .visit(&ctx)
        .map_err(|e| MiniscriptError::DescriptorVisitorError(e))?;

    let script_buf =
        script::build_script(&ctx).map_err(|e| MiniscriptError::ScriptBuilderError(e))?;
    Ok((ctx, script_buf))
}
