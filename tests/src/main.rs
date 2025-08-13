mod ast_printer;

use std::str::FromStr;

use bitcoin::{PublicKey, XOnlyPublicKey};
use miniscript_rs::MiniscriptError;
fn main() {
    let x_only = "0202020202020202020202020202020202020202020202020202020202020202";
    let pub_key = "020202020202020202020202020202020202020202020202020202020202020202";

    let scripts = vec![
        format!("tr(and_v(v:pk({}),pk({})))", x_only, x_only),
        format!("sh(wsh(and_v(v:pk({}),pk({}))))", pub_key, pub_key),
    ];

    for script in scripts {
        println!("--------------------------------");

        println!("script: {}\n", script);

        if let Err(e) = execute_script(&script) {
            println!("error executing script: {:?}", e);
        }
    }
}

fn execute_script<'a>(script: &'a str) -> Result<(), MiniscriptError<'a>> {
    let mut ast_printer = ast_printer::ASTPrinter::new();
    let (ctx, script_buf) = miniscript_rs::parse_script(script)?;
    println!("ast: {}", ast_printer.print_ast(&ctx));
    println!("bitcoin script: {:?}", script_buf.to_asm_string());
    Ok(())
}
