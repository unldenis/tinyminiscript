use std::{ops::Deref, rc::Rc, str::FromStr};

use bitcoin::{PublicKey, XOnlyPublicKey};
use tinyminiscript::{
    MiniscriptError,
};
fn main() {
    let x_only = "0202020202020202020202020202020202020202020202020202020202020202";
    let pub_key = "020202020202020202020202020202020202020202020202020202020202020202";

    if true {
        let scripts = vec![
            "sh(wsh(0))".to_string(),
            "sh(uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuunuuuuunuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuunuuuuunuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu:0)".to_string(),
            format!("tr(and_v(v:pk({}),pk({})))", x_only, x_only),
            format!("sh(wsh(and_v(v:pk({}),pk({}))))", pub_key, pub_key),
            "wsh(multi(1,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc))".to_string(),
            format!("sh(or_d(pk({}),pk({})))", pub_key, pub_key),
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
            "sh(u:after(05))".to_string(),
            "sh(dvu:0)".to_string(),
            "sh(wsh(dvu:0))#error".to_string(),
            "sh(older(+1))".to_string(),
            "sh(older(2))".to_string(),
            "sh(u:after(3802199998))".to_string(),
            "sh(utvjtvntvdv:0)".to_string(),
            "sh(uu:thresh(01,thresh(1,0)))".to_string(),
            "sh(hash160(vvvvvvvvvvvvvvvvvvvv))".to_string(),
            "sh(ripemd160(ccccccccccccccccccCCCCCCcccccccccccccc9c))".to_string(),
        ];

        for script in scripts {
            println!("--------------------------------");

            println!("script: {}\n", script);

            if let Err(e) = execute_script(&script) {
                println!("error executing script: {:?}", e);
            }
        }
    }

    println!("--------------------------------");

    let key = "[aabbccdd/10'/123]tpubDAenfwNu5GyCJWv8oqRAckdKMSUoZjgVF5p8WvQwHQeXjDhAHmGrPa4a4y2Fn7HF2nfCLefJanHV3ny1UY25MRVogizB2zRUdAo7Tr9XAjm/10/*";
    let script = format!("wsh(or_d(pk({}),older(12960)))", key);

    println!("original script  : {}", script);

    let mut ctx = tinyminiscript::parse_script(&script).unwrap();
    println!("serialized before: {}", ctx.serialize());
    ctx.derive(22).unwrap();
    println!("serialized after : {}", ctx.serialize());

    ctx.iterate_keys_mut(|key| {
        println!("before : {:?}", key.identifier());

        let derived = key.derive(22).unwrap();

        *key = derived;
    });

    // read file content and parse it
    let file_content = std::fs::read_to_string("/home/user/rust/f-miniscript/fuzz/artifacts/parsing/crash-b5d31129661ca6ecf81d29d7078d8306ebb9a880").unwrap();
    let scripts = file_content.lines().collect::<Vec<&str>>();
    for script in scripts {
        println!("--------------------------------");
        println!("script: {}", script);
        execute_script(script).unwrap();
    }
}
#[derive(Debug)]
enum Error<'a> {
    Miniscript(MiniscriptError<'a>),
    // Satisfaction(SatisfyError),
}

fn execute_script<'a>(script: &'a str) -> Result<(), Error<'a>> {
    let ctx = tinyminiscript::parse_script(script).map_err(Error::Miniscript)?;
    let script_buf = tinyminiscript::script::build_script(&ctx)
        .map_err(MiniscriptError::ScriptBuilderError)
        .map_err(Error::Miniscript)?;
    // println!("ast: {}", ctx.print_ast());
    // println!("bitcoin script: {:?}", script_buf.to_asm_string());

    println!("bitcoin serialized: {}", ctx.serialize());

    //println!("nodes: {:?}", ctx.nodes);
    // let satisfied = ctx
    //     .satisfy(&TestSatisfier {})
    //     .map_err(Error::Satisfaction)?;
    // println!("satisfied: {:?}", satisfied.sat);

    Ok(())
}

// struct TestSatisfier {}

// impl Satisfier for TestSatisfier {
//     fn check_older(&self, locktime: i64) -> Option<bool> {
//         None
//     }

//     fn check_after(&self, locktime: i64) -> Option<bool> {
//         None
//     }

//     fn sign(&self, pubkey: &dyn tinyminiscript::parser::keys::PublicKeyTrait) -> Option<(Vec<u8>, bool)> {
//         Some((Vec::new(), false))
//     }

//     fn preimage(
//         &self,
//         hash_func: tinyminiscript::satisfy::HashFunc,
//         hash: &[u8],
//     ) -> Option<(Vec<u8>, bool)> {
//         None
//     }
// }
