#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    use tinyminiscript::{parse_script, parser::Fragment};

    let script = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };

    use miniscript::Descriptor;
    use std::str::FromStr;

    let ms_descriptor = Descriptor::<miniscript::bitcoin::PublicKey>::from_str(script);
    let ts_descriptor = parse_script(script);

    match (ms_descriptor, ts_descriptor) {
        (Ok(desc), Ok(ctx)) => {
            let ms_script = desc.explicit_script().unwrap().to_asm_string();
            let ts_script = ctx.build_script().unwrap().to_asm_string();

            if ms_script != ts_script {
                panic!("Script: '{:?}'\nMiniscript : '{:?}'\nTinyMiniscript : '{:?}'", script, ms_script, ts_script);
            }
        }
        _ => return,
    }
});
