mod ast_printer;

use std::str::FromStr;

use bitcoin::PublicKey;
use miniscript_rs::{MiniscriptError, model::KeyRegistry};
fn main() {
    let pubkey1 =
        PublicKey::from_str("020202020202020202020202020202020202020202020202020202020202020202")
            .unwrap();
    let not_compressed_pubkey = PublicKey::new_uncompressed(pubkey1.inner);

    let mut builder = miniscript_rs::model::KeyRegistry::new();
    builder.add_key("pubkey1", pubkey1);
    builder.add_key("pubkey2", not_compressed_pubkey);

    let scripts = vec![
        "tr(and_v(v:pk(pubkey1),pk(pubkey2)))",
        "sh(wsh(and_v(v:pk(pubkey1),pk(pubkey2))))",
    ];

    for script in scripts {
        println!("--------------------------------");

        println!("script: {}\n", script);

        if let Err(e) = execute_script(script, &builder) {
            println!("error executing script: {:?}", e);
        }
    }
}

fn execute_script<'a, 'b>(
    script: &'a str,
    builder: &'b KeyRegistry<'a>,
) -> Result<(), MiniscriptError<'a>> {
    let mut ast_printer = ast_printer::ASTPrinter::new();
    let (ctx, script_buf) = miniscript_rs::parse_script(script, &builder)?;
    // println!("ast: {}", ast_printer.print_ast(&ctx));
    println!("bitcoin script: {:?}", script_buf.to_asm_string());
    Ok(())
}
