#[macro_use]
extern crate afl;
extern crate tinyminiscript;
extern crate miniscript;

fn main() {
    fuzz!(|data: &[u8]| {
        if let Ok(script) = std::str::from_utf8(data) {
            use miniscript::Descriptor;
            use std::str::FromStr;

            let ms_descriptor = Descriptor::<miniscript::bitcoin::PublicKey>::from_str(script);
            let ts_descriptor = tinyminiscript::parse_script(script);
        
            match (ms_descriptor, ts_descriptor) {
                (Ok(_), Ok(_)) => {}
                (Err(e), Ok(ctx)) => {
        
                    let err  = format!("{:?}", e);
                    // if err.contains("ExpectedChar(')')") {
                    //     return;
                    // }
        
                    println!("AST:{}", ctx.serialize());
                    panic!("Invalid descriptor accepted: '{}' (expected error {:?})", script, e);
                }
                (Ok(_), Err(e)) => {
                    panic!("Valid descriptor rejected: '{}' (got error {:?})", script, e);
                }
                _ => return,
            }
        }
    });
}
