use f_miniscript::{lexer::Lexer, parser::Parser};

fn main() {
    let script = "and_v(v:pk(K),pk(A))";

    let scripts = vec![
        "0",
        "1",
        "pk_k(K)",
        "pk_h([d6043800/0'/0'/18']03efdee34c0009fd175f3b20b5e5a5517fd5d16746f2e635b44617adafeaebc388)#4ahsl9pk",
        "pk(K)",
        "pkh(K)",
    ];

    for script in scripts {
        println!("Parsing: {}\n", script);
        let mut lexer = Lexer::new(script);
        let parser = Parser::new();
        match parser.parse(&mut lexer) {
            Ok(fragment) => {
                println!("Fragment: {:?}", fragment);
            }
            Err(err) => {
                println!("Error: {:?}", err);
            }
        }
        println!("--------------------------------");
    }

    // another script
    // let script = "pkh([d6043800/0'/0'/18']03efdee34c0009fd175f3b20b5e5a5517fd5d16746f2e635b44617adafeaebc388)#4ahsl9pk";
    // println!("Parsing: {}\n", script);
    // let lexer = Lexer::new(script);
    // for token in lexer {
    //     match token {
    //         Ok(token) => {
    //             println!("{}", token);
    //         }
    //         Err(err) => {
    //             println!("Error: {:?}", err);
    //         }
    //     }
    // }
}
