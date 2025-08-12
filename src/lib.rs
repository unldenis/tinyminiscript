#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod descriptor;
pub mod model;
pub mod parser;
pub mod script;
pub mod type_checker;

pub extern crate alloc;

//

use bitcoin::ScriptBuf;
use model::KeyRegistry;
use parser::ASTVisitor;

use crate::{parser::ParserContext, type_checker::TypeInfo};

#[derive(Debug)]
pub enum MiniscriptError<'a> {
    ParserError(parser::ParseError<'a>),
    TypeCheckerError(type_checker::CorrectnessPropertiesVisitorError),
    DescriptorVisitorError(descriptor::DescriptorVisitorError<'a>),
    ScriptBuilderError(script::ScriptBuilderError<'a>),
}

pub fn parse_script<'a>(
    script: &'a str,
    script_builder: &KeyRegistry<'a>,
) -> Result<(ParserContext<'a>, ScriptBuf), MiniscriptError<'a>> {
    let ctx = parser::parse(script).map_err(|e| MiniscriptError::ParserError(e))?;

    // type check the ast
    let _: TypeInfo = type_checker::CorrectnessPropertiesVisitor::new()
        .visit(&ctx)
        .map_err(|e| MiniscriptError::TypeCheckerError(e))?;

    // descriptor visitor
    let _: () = descriptor::DescriptorValidator::new(script_builder)
        .visit(&ctx)
        .map_err(|e| MiniscriptError::DescriptorVisitorError(e))?;

    let script_buf = script::build_script(script_builder, &ctx)
        .map_err(|e| MiniscriptError::ScriptBuilderError(e))?;
    Ok((ctx, script_buf))
}
