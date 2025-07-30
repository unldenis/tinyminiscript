use f_miniscript::lexer::{Lexer, Token};

fn main() {
    let script = "and_v(v:pk(K),pk(A))";
    let lexer = Lexer::new(script);
    for token in lexer {
        println!("{:?}", token);
    }


    println!("--------------------------------");

    // another script
    let script = "pkh([d6043800/0'/0'/18']03efdee34c0009fd175f3b20b5e5a5517fd5d16746f2e635b44617adafeaebc388)#4ahsl9pk";
    let lexer = Lexer::new(script);
    for token in lexer {
        println!("{:?}", token);
    }
}
