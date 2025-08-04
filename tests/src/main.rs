mod visitor;

use f_miniscript::{
    lexer::Lexer,
    parser::{self, Context},
};

use crate::visitor::StringBufferVisitor;

fn main() {
    // let script = "and_v(v:pk(K),pk(A))";

    let scripts = vec![
        "0",
        "1",
        "pk_k(K)",
        "pk_h([d6043800/0'/0'/18']03efdee34c0009fd175f3b20b5e5a5517fd5d16746f2e635b44617adafeaebc388)#4ahsl9pk",
        "pk(K)",
        "pkh(K)",
        "older(555)",
        "after(13)",
        "after(0)",
        "older(1)",
        "sha256(h)",
        "hash256(h)",
        "ripemd160(h)",
        "hash160(h)",
        "andor(pk(K),pk(A),pk(B))",
        "andor(pk(K),pk(A),andor(pk(B),pk(C),pk(D)))",
        "and_v(pk(K),pk(A))",
        "and_v(pk(K),and_v(pk(A),pk(B)))",
        "and_b(pk(K),pk(A))",
        "and_b(pk(K),and_v(pk(A),andor(pk(B),pk(C),pk(D))))",
    ];

    for script in scripts {
        println!("Parsing: {}\n", script);
        let mut lexer = Lexer::new(script);

        let mut ctx = Context::new(&mut lexer);
        match parser::parse(&mut ctx) {
            Ok(fragment) => {
                println!("Fragment: {:?}", fragment);

                // Example: Using the string buffer visitor to get a formatted tree
                println!("\nString representation:");
                let mut string_visitor = StringBufferVisitor::new();
                ctx.visit_fragment(&fragment, &mut string_visitor);
                println!("{}", string_visitor.get_result());
            }
            Err(err) => {
                println!("Error: {:?}", err);
                break;
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
