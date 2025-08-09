#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

pub mod parser;
pub mod script;
pub mod type_checker;

pub extern crate alloc;

//

use bitcoin::ScriptBuf;
use parser::ASTVisitor;
use script::ScriptBuilder;

use crate::{parser::AST, type_checker::TypeInfo};

#[derive(Debug)]
pub enum MiniscriptError<'a> {
    ParserError(parser::ParseError<'a>),
    TypeCheckerError(type_checker::CorrectnessPropertiesVisitorError),
    ScriptBuilderError(script::ScriptBuilderError<'a>),
}

pub fn parse_script<'a>(
    script: &'a str,
    script_builder: &ScriptBuilder<'a>,
) -> Result<(AST<'a>, ScriptBuf), MiniscriptError<'a>> {
    let ast = parser::parse(script).map_err(|e| MiniscriptError::ParserError(e))?;

    // type check the ast
    let _: TypeInfo = type_checker::CorrectnessPropertiesVisitor::new()
        .visit_ast(&ast)
        .map_err(|e| MiniscriptError::TypeCheckerError(e))?;

    let script_buf = script::build_script(script_builder, &ast)
        .map_err(|e| MiniscriptError::ScriptBuilderError(e))?;
    Ok((ast, script_buf))
}
