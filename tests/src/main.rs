mod ast_printer;

use std::str::FromStr;

use bitcoin::{PublicKey, XOnlyPublicKey};
use tinyminiscript::MiniscriptError;
fn main() {
    let x_only = "0202020202020202020202020202020202020202020202020202020202020202";
    let pub_key = "020202020202020202020202020202020202020202020202020202020202020202";

    let scripts = vec![
        format!("tr(and_v(v:pk({}),pk({})))", x_only, x_only),
        format!("sh(wsh(and_v(v:pk({}),pk({}))))", pub_key, pub_key),
        "wsh(multi(1,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc))".to_string(),
        format!("or_d(pk({}),pk({}))", pub_key, pub_key),
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
    let (ctx, script_buf) = tinyminiscript::parse_script(script)?;
    println!("ast: {}", ast_printer.print_ast(&ctx));
    println!("bitcoin script: {:?}", script_buf.to_asm_string());
    Ok(())
}
