mod ast_printer;

use std::str::FromStr;

use bitcoin::PublicKey;

fn main() {
    let pubkey1 =
        PublicKey::from_str("020202020202020202020202020202020202020202020202020202020202020202")
            .unwrap();

    let mut builder = f_miniscript::script::ScriptBuilder::new();
    builder.add_key("pubkey1".to_string(), pubkey1);
    builder.add_key("pubkey2".to_string(), pubkey1);

    let mut ast_printer = ast_printer::ASTPrinter::new();

    let script = "or_d(pk(pubkey1),and_v(v:pk(pubkey2),older(52560)))";
    let (ast, script_buf) = f_miniscript::parse_script(script, &builder).unwrap();
    println!("ast: {}", ast_printer.print_ast(&ast));
    println!("script: {:?}", script_buf.to_asm_string());

    println!("--------------------------------");
    // second script

    let script = "and_v(v:pk(pubkey1),pk(pubkey2))";
    let (ast, script_buf) = f_miniscript::parse_script(script, &builder).unwrap();
    println!("ast: {}", ast_printer.print_ast(&ast));
    println!("script: {:?}", script_buf.to_asm_string());
}
