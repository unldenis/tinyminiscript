use std::fmt::format;

use tinyminiscript::MiniscriptError;

fn main() {
    println!("\n🚀 Starting Miniscript Test Suite");
    println!("=====================================");
    
    // Run all test categories
    test_basic_scripts();
    test_key_derivation();
    test_script_building();
    test_miniscript();
    test_diffs();

    println!("\n\n\n✅ All tests completed!");
}

/// Test basic script parsing and execution
fn test_basic_scripts() {
    println!("\n📝 Testing Basic Scripts");
    println!("------------------------");
    
    let x_only = "0202020202020202020202020202020202020202020202020202020202020202";
    let pub_key = "020202020202020202020202020202020202020202020202020202020202020202";

    let script_with_keys_1 = format!("tr(and_v(v:pk({}),pk({})))", x_only, x_only);
    let script_with_keys_2 = format!("sh(wsh(and_v(v:pk({}),pk({}))))", pub_key, pub_key);
    let script_with_keys_3 = format!("sh(or_d(pk({}),pk({})))", pub_key, pub_key);
    let script_with_keys_4 = format!("tr(pk({})):", x_only);
    let script_with_keys_5 = format!("tr({})", x_only);
    let script_with_keys_6 = format!("tr({},pk({}))", x_only, x_only);

    let scripts = vec![
        // Basic scripts
        "sh(wsh(0))",
        "1",
        "tr(0)",
        "sh(1)",
        
        // Scripts with keys
        &script_with_keys_1,
        &script_with_keys_2,
        &script_with_keys_3,
        &script_with_keys_4,
        &script_with_keys_5,
        &script_with_keys_6,
        
        // Multi-signature scripts
        "wsh(multi(1,022f8bde4d1a07209355b4a7250a5c5128e88b84bddc619ab7cba8d569b240efe4,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc))",
        
        // Time-locked scripts
        "sh(u:after(05))",
        "sh(older(+1))",
        "sh(older(2))",
        "sh(u:after(3802199998))",
        "tr(older(8))",
        
        // Complex scripts with various fragments
        "sh(n:0)",
        "tr(n:0)",
        "sh(j:1)",
        "sh(s:1)",
        "sh(dvu:0)",
        "sh(wsh(dvu:0))#error",
        "sh(utvjtvntvdv:0)",
        "sh(uu:thresh(01,thresh(1,0)))",
        "sh(hash160(vvvvvvvvvvvvvvvvvvvv))",
        "sh(ripemd160(ccccccccccccccccccCCCCCCcccccccccccccc9c))",
        "tr(DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD,l:0)",
        "sh(j:and_b(dv:0,su:0))",
        "sh(thresh(2,0,a:thresh(1,0,a:0,an:0,a:0)a:0))",
        "sh(0)#7h0w2xvg"
    ];

    for (i, script) in scripts.iter().enumerate() {
        println!("\n\n🔍 Test {}: {}", i + 1, script);
        println!("{}", "─".repeat(50));
        
        match execute_script(script) {
            Ok(_) => println!("✅ Script executed successfully"),
            Err(e) => println!("❌ Error executing script: {:?}", e),
        }
    }
}

/// Test key derivation functionality
fn test_key_derivation() {
    println!("\n\n🔑 Testing Key Derivation");
    println!("-------------------------");
    
    let key = "[aabbccdd/10'/123]tpubDAenfwNu5GyCJWv8oqRAckdKMSUoZjgVF5p8WvQwHQeXjDhAHmGrPa4a4y2Fn7HF2nfCLefJanHV3ny1UY25MRVogizB2zRUdAo7Tr9XAjm/10/*";
    let script = format!("wsh(or_d(pk({}),older(12960)))", key);

    println!("📋 Original script: {}", script);

    match tinyminiscript::parse_script(&script) {
        Ok(mut ctx) => {
            println!("📦 Serialized before derivation: {}", ctx.serialize());
            
            if let Err(e) = ctx.derive(22) {
                println!("❌ Error during derivation: {:?}", e);
                return;
            }
            
            println!("📦 Serialized after derivation: {}", ctx.serialize());

            ctx.iterate_keys_mut(|key| {
                println!("🔧 Before derivation: {:?}", key.identifier());
                
                match key.derive(22) {
                    Ok(derived) => {
                        *key = derived;
                        println!("🔧 After derivation: {:?}", key.identifier());
                    }
                    Err(e) => println!("❌ Key derivation error: {:?}", e),
                }
            });
        }
        Err(e) => println!("❌ Error parsing script: {:?}", e),
    }
}

/// Test script building functionality
fn test_script_building() {
    println!("\n\n🔨 Testing Script Building");
    println!("-------------------------");

    let pub_key = "020202020202020202020202020202020202020202020202020202020202020202";
    let equalverify = format!("wsh(or_d(pk({}),and_v(v:pk({}),older(52560))))", pub_key, pub_key);
    let scripts = vec![
        "sh(n:1)",
        "sh(ntvtvnnnnnntvnnnjnnndvn:0)",
        "pkh(033333333333333333333333333333333333333333333333333333333333333333)",
        "wsh(thresh(1,0))",
        "wsh(tv:thresh(1,u:0))",
        equalverify.as_str()
    ];

    for (i, script) in scripts.iter().enumerate() {
        println!("\n\n🔍 Build Test {}: {}", i + 1, script);
        println!("{}", "─".repeat(50));
        
        match tinyminiscript::parse_script(script) {
            Ok(ctx) => {
                match ctx.build_script() {
                    Ok(script_buf) => {
                        println!("✅ Script built successfully");
                        println!("📜 Bitcoin script: {}", script_buf.to_asm_string());
                    }
                    Err(e) => println!("❌ Error building script: {:?}", e),
                }
            }
            Err(e) => println!("❌ Error parsing script: {:?}", e),
        }
    }
}

fn test_miniscript() {
    println!("\n\n🔍 Testing Miniscript");
    println!("-------------------------");

    let scripts = vec![
        "tr(DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD,l:0)",
    ];

    for (i, script) in scripts.iter().enumerate() {
        println!("\n\n🔍 Miniscript Test {}: {}", i + 1, script);
        println!("{}", "─".repeat(50));
        
        use miniscript::Descriptor;
        use miniscript::bitcoin;
        use std::str::FromStr;
        match Descriptor::<bitcoin::PublicKey>::from_str(script) {
            Ok(desc) => {
                println!("✅ Miniscript descriptor built successfully");
                println!("📜 Miniscript descriptor: {}", desc);
            }
            Err(e) => println!("❌ Error building miniscript descriptor: {:?}", e),
        }
    }
}

fn test_diffs() {
    println!("\n\n🔍 Testing Diffs");
    println!("-------------------------");

    let scripts = vec![
        "pk(021607130607051209051304060307030704205091903060909060415090215072)",
        "sh(wsh(and_n(ljjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjjj:pk(020513060604181215120913141616141318171817121906020906090318181704),pk(020606161514070203071418190717181303181315151817150717021304131309))))",
        "sh(wsh(and_n(lnnnntvunnntvntvunuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuulnlll:pk(020513121919060603051713070408070204050605080413191317319040440514),pk(020612030408191812180952031904040416070406030505021906020517070909))))",
        "tr(020202020202020212131610202020202121316121618171818121715181919190)",
        "tr(3202020020202020202020202020202121316121618171818121715181919190)"

    ];



    for (i, script) in scripts.iter().enumerate() {
        println!("\n\n🔍 Diff Test {}: {}", i + 1, script);
        println!("{}", "─".repeat(50));

        use miniscript::Descriptor;
        use miniscript::bitcoin;
        use std::str::FromStr;
        match Descriptor::<bitcoin::PublicKey>::from_str(script) {
            Ok(desc) => {
                println!("✅ Miniscript descriptor built successfully");
                println!("📜 Miniscript descriptor: {}", desc);
                let ms_script = desc.explicit_script();
                if let Ok(script) = ms_script {
                    println!("📜 Miniscript script: {}", script.to_asm_string());
                } else {
                    println!("❌ Miniscript script is None");
                }
            }
            Err(e) => println!("❌ Error building miniscript descriptor: {:?}", e),
        }

        let ctx = tinyminiscript::parse_script(script);
        if let Err(e) = ctx {
            println!("❌ Error building tinyminiscript descriptor: {:?}", e);
        } else {
            let ctx = ctx.unwrap();
            println!("✅ TinyMiniscript descriptor built successfully");
            println!("📜 TinyMiniscript descriptor: {}", ctx.serialize());
            let ts_script = ctx.build_script();
            if let Ok(script) = ts_script {
                println!("📜 TinyMiniscript script: {}", script.to_asm_string());
            } else {
                println!("❌ TinyMiniscript script is None");
            }

        }
        
    }
}

#[derive(Debug)]
#[allow(dead_code)]
enum Error<'a> {
    Miniscript(MiniscriptError<'a>),
}

/// Execute a script and log the results
fn execute_script<'a>(script: &'a str) -> Result<(), Error<'a>> {
    let ctx = tinyminiscript::parse_script(script).map_err(Error::Miniscript)?;
    
    println!("📦 Bitcoin serialized: {}", ctx.serialize());
    
    Ok(())
}