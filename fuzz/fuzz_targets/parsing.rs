#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use tinyminiscript::{Context, parser::Fragment};

    let script = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    use miniscript::Descriptor;
    use std::str::FromStr;

    let ms_descriptor = Descriptor::<miniscript::bitcoin::PublicKey>::from_str(script);
    let ts_descriptor = Context::try_from(script);

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
});
