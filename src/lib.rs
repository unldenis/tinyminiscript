#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

#[macro_use]
mod macros;
pub mod parser;
pub mod type_checker;

pub extern crate alloc;
