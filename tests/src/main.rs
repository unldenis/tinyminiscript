use std::str::FromStr;

use bitcoin::{PublicKey, XOnlyPublicKey};
use tinyminiscript::{
    MiniscriptError,
    satisfy::{Satisfier, SatisfyError},
};
fn main() {
    let x_only = "0202020202020202020202020202020202020202020202020202020202020202";
    let pub_key = "020202020202020202020202020202020202020202020202020202020202020202";

    if true {
        let scripts = vec![
            "sh(uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuunuuuuunuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuunuuuuunuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu:0)".to_string(),
            format!("tr(and_v(v:pk({}),pk({})))", x_only, x_only),
            format!("sh(wsh(and_v(v:pk({}),pk({}))))", pub_key, pub_key),
            "wsh(multi(1,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc))".to_string(),
            format!("or_d(pk({}),pk({}))", pub_key, pub_key),
        //  "l:0p0n#:0pnnnnnnnnnnnnnnnnnnl:nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnl:nnnnnnnnnnnnnnnnnnnnnnnnnnl:nnnnnnnnnnnnnnnnnnnnnnnnnnAnnnnnnnnnnnnnnnnnnnnnnnl:nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnAnnnnnnnnnnnnnnnnnnnnnnnnAnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnl:nnnnnnnnnnnnnnnnnnnnnnnnnnl:nnnnnnnnnnnnnnnnnnnnnnnnnnAnnnnnnnnnnnnnnnnnnnnnnnl:nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnAnnnnnnnnnnnnnnnnnnnnnnnnnnnnnl:nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnl:nnnnnnnnl:nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn0wnnnnnnnnnnnnnnnnAnnnnnnnnnnnnnnnnnnnnnnnnAnnnnnn:0".to_string()
            "1".to_string(),
            format!("tr(pk({})):", x_only),
            "tr(0)".to_string(),
            "sh(1)".to_string(),
            "tr(n:0)".to_string(),
            "sh(j:1)".to_string(),
            "sh(s:1)".to_string(),
            "sh(vuuuu:1)".to_string(),
            "sh(uuuuuuuuuuuuuu:uuuuuu:1)".to_string(),
            "tr(u:1)".to_string(),
            "sh(uunnnnnnnnnnnnnnnnnnuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuunnnnnnnuuu:1)".to_string(),
            "wsh(uuzuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu:0)".to_string(),
            "wsh(uuzuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu:0)".to_string(),
            "sh(undvuuuuuuullllllluundvuuuuuuullllllluu:0)".to_string(),
        ];

        for script in scripts {
            println!("--------------------------------");

            println!("script: {}\n", script);

            if let Err(e) = execute_script(&script) {
                println!("error executing script: {:?}", e);
            }
        }
    }

    let read_file = std::fs::read_to_string("/home/user/rust/f-miniscript/fuzz/artifacts/parsing/crash-eb664da22b5a06fcd77c10a9cb3ee08d2a43dc96").unwrap();

    println!("\n\nFile script --------------------------------");

    use miniscript::Descriptor;

    match Descriptor::<PublicKey>::from_str(&read_file) {
        Ok(_) => {
            println!("miniscript: descriptor parsed successfully");
        }
        Err(e) => {
            println!("miniscript: error parsing descriptor: {:?}", e);
        }
    }

    match execute_script(&read_file) {
        Ok(_) => {
            println!("tinyminiscript: descriptor parsed successfully");
        }
        Err(e) => {
            println!("tinyminiscript: error parsing descriptor: {:?}", e);
        }
    }
}
#[derive(Debug)]
enum Error<'a> {
    Miniscript(MiniscriptError<'a>),
    Satisfaction(SatisfyError),
}

fn execute_script<'a>(script: &'a str) -> Result<(), Error<'a>> {
    let (ctx, script_buf) = tinyminiscript::parse_script(script).map_err(Error::Miniscript)?;
    // println!("ast: {}", ctx.print_ast());
    // println!("bitcoin script: {:?}", script_buf.to_asm_string());

    println!("bitcoin script size: {} bytes", script_buf.len());

    //println!("nodes: {:?}", ctx.nodes);
    if true {
        // let satisfied = ctx
        //     .satisfy(&TestSatisfier {})
        //     .map_err(Error::Satisfaction)?;
        // println!("satisfied: {:?}", satisfied.sat);
    }

    Ok(())
}

struct TestSatisfier {}

impl Satisfier for TestSatisfier {
    fn check_older(&self, locktime: i64) -> Option<bool> {
        None
    }

    fn check_after(&self, locktime: i64) -> Option<bool> {
        None
    }

    fn sign(&self, pubkey: &dyn tinyminiscript::parser::KeyTypeTrait) -> Option<(Vec<u8>, bool)> {
        Some((Vec::new(), false))
    }

    fn preimage(
        &self,
        hash_func: tinyminiscript::satisfy::HashFunc,
        hash: &[u8],
    ) -> Option<(Vec<u8>, bool)> {
        None
    }
}
