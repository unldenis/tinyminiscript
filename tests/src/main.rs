use std::str::FromStr;

use bitcoin::{PublicKey, XOnlyPublicKey};
use tinyminiscript::{
    MiniscriptError,
    satisfy::{Satisfier, SatisfyError},
};
fn main() {
    let x_only = "0202020202020202020202020202020202020202020202020202020202020202";
    let pub_key = "020202020202020202020202020202020202020202020202020202020202020202";

    let scripts = vec![
        format!("tr(and_v(v:pk({}),pk({})))", x_only, x_only),
        format!("sh(wsh(and_v(v:pk({}),pk({}))))", pub_key, pub_key),
        "wsh(multi(1,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc))".to_string(),
        format!("or_d(pk({}),pk({}))", pub_key, pub_key),
      //  "l:0p0n#:0pnnnnnnnnnnnnnnnnnnl:nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnl:nnnnnnnnnnnnnnnnnnnnnnnnnnl:nnnnnnnnnnnnnnnnnnnnnnnnnnAnnnnnnnnnnnnnnnnnnnnnnnl:nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnAnnnnnnnnnnnnnnnnnnnnnnnnAnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnl:nnnnnnnnnnnnnnnnnnnnnnnnnnl:nnnnnnnnnnnnnnnnnnnnnnnnnnAnnnnnnnnnnnnnnnnnnnnnnnl:nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnAnnnnnnnnnnnnnnnnnnnnnnnnnnnnnl:nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnl:nnnnnnnnl:nnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnnn0wnnnnnnnnnnnnnnnnAnnnnnnnnnnnnnnnnnnnnnnnnAnnnnnn:0".to_string()
        "1".to_string(),
        format!("tr(pk({})):", x_only),
        "tr(0)".to_string(),
        "tr(aq:0)".to_string(),
    ];

    for script in scripts {
        println!("--------------------------------");

        println!("script: {}\n", script);

        if let Err(e) = execute_script(&script) {
            println!("error executing script: {:?}", e);
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
    println!("ast: {}", ctx.print_ast());
    println!("bitcoin script: {:?}", script_buf.to_asm_string());

    println!("nodes: {:?}", ctx.nodes);
    if true {
        let satisfied = ctx
            .satisfy(&TestSatisfier {})
            .map_err(Error::Satisfaction)?;
        println!("satisfied: {:?}", satisfied);
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

    fn sign(&self, pubkey: &tinyminiscript::parser::KeyType) -> Option<(Vec<u8>, bool)> {
        match pubkey {
            tinyminiscript::parser::KeyType::PublicKey(pubkey) => Some((Vec::new(), false)),
            tinyminiscript::parser::KeyType::XOnlyPublicKey(pubkey) => Some((Vec::new(), false)),
        }
    }

    fn preimage(
        &self,
        hash_func: tinyminiscript::satisfy::HashFunc,
        hash: &[u8],
    ) -> Option<(Vec<u8>, bool)> {
        None
    }
}
