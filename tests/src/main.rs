mod ast_printer;

use std::str::FromStr;

use bitcoin::{Address, NetworkKind, PublicKey, params::Params};

fn main() {
    let pubkey1 =
        PublicKey::from_str("020202020202020202020202020202020202020202020202020202020202020202")
            .unwrap();

    let mut builder = miniscript_rs::script::ScriptBuilder::new();
    builder.add_key("pubkey1".to_string(), pubkey1);
    builder.add_key("pubkey2".to_string(), pubkey1);

    let mut ast_printer = ast_printer::ASTPrinter::new();

    let script = "or_d(pk(pubkey1),and_v(v:pk(pubkey2),older(52560)))";
    let (ast, script_buf) = miniscript_rs::parse_script(script, &builder).unwrap();

    println!("ast: {}", ast_printer.print_ast(&ast));
    println!("script: {:?}", script_buf.to_asm_string());
    let address = Address::p2sh(script_buf.as_script(), NetworkKind::Main).unwrap();
    println!("address: {}", address);

    println!("--------------------------------");
    // second script

    let script = "and_v(v:pk(pubkey1),pk(pubkey2))";
    let (ast, script_buf) = miniscript_rs::parse_script(script, &builder).unwrap();
    println!("ast: {}", ast_printer.print_ast(&ast));
    println!("script: {:?}", script_buf.to_asm_string());
    let address = Address::p2sh(script_buf.as_script(), NetworkKind::Main).unwrap();
    println!("address: {}", address);
}
