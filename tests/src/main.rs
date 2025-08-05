mod visitor;

use f_miniscript::{
    lexer::Lexer,
    parser::{self, Context},
    visitor::CorrectnessPropertiesVisitor,
};

use crate::visitor::StringBufferVisitor;

fn main() {
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
        "and_n(pk(K),pk(A))",
        "or_b(pk(K),pk(A))",
        "or_c(pk(K),pk(A))",
        "or_d(pk(K),pk(A))",
        "or_i(pk(K),pk(A))",
        "thresh(2,pk(K),pk(A),pk(B))",
        "thresh(2,pk(K),and_v(pk(A),pk(B)),pk(C))",
        "multi(2,K,A,B)",
        "multi_a(2,K,A,B)",
        "and_v(v:pk(K),pk(A))",
        // PARSER ERRORS
        "pk(2)",
    ];

    for script in scripts {
        println!("Parsing: {}\n", script);

        let mut ctx = Context::new(script);
        match parser::parse(&mut ctx) {
            Ok(fragment) => {
                println!("Fragment: {:?}", fragment);

                // Example: Using the string buffer visitor to get a formatted tree
                println!("\nString representation:");
                let mut string_visitor = StringBufferVisitor::new();
                let result = ctx.visit_node(&fragment, &mut string_visitor);
                match result {
                    Ok(_) => {
                        println!("{}", string_visitor.get_result());
                    }
                    Err(err) => {
                        println!("String representation Error: {:?}", err);
                    }
                }

                let mut correctness_visitor = CorrectnessPropertiesVisitor::new();
                let result = ctx.visit_node(&fragment, &mut correctness_visitor);
                match result {
                    Ok(_) => {
                        println!("Correctness properties: {:?}", result);
                    }
                    Err(err) => {
                        println!("Correctness properties Error: {:?}", err);
                    }
                }
            }
            Err(err) => {
                println!("Parser Error: {:?}", err);
                break;
            }
        }
        println!(
            "------------------------------------------------------------------------------------------------"
        );
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
