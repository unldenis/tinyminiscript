use crate::parser::{AST, ASTVisitor, Context, Fragment};

use alloc::format;
use alloc::string::String;
use alloc::string::ToString;

pub struct TranslatorVisitor {}

impl TranslatorVisitor {
    pub fn new() -> Self {
        Self {}
    }
}

#[derive(Debug)]
pub enum TranslatorVisitorError {}

impl ASTVisitor<String> for TranslatorVisitor {
    type Error = TranslatorVisitorError;

    fn visit_ast(&mut self, ctx: &Context, node: &AST) -> Result<String, Self::Error> {
        match &node.fragment {
            Fragment::False => Ok(String::from("0")),
            Fragment::True => Ok(String::from("1")),
            Fragment::PkK { key } => Ok(format!("<{}>", key.to_string())),
            Fragment::PkH { key } => Ok(format!(
                "DUP HASH160 <HASH160({})> EQUALVERIFY CHECKSIG",
                key.to_string()
            )),
            Fragment::Older { n } => Ok(format!("<{}> CHECKSEQUENCEVERIFY", n)),
            Fragment::After { n } => Ok(format!("<{}> CHECKLOCKTIMEVERIFY", n)),
            Fragment::Sha256 { h } => Ok(format!(
                "SIZE <20> EQUALVERIFY SHA256 <{}> EQUAL",
                h.to_string()
            )),
            Fragment::Hash256 { h } => Ok(format!(
                "SIZE <20> EQUALVERIFY HASH256 <{}> EQUAL",
                h.to_string()
            )),
            Fragment::Ripemd160 { h } => Ok(format!(
                "SIZE <20> EQUALVERIFY RIPEMD160 <{}> EQUAL",
                h.to_string()
            )),
            Fragment::Hash160 { h } => Ok(format!(
                "SIZE <20> EQUALVERIFY HASH160 <{}> EQUAL",
                h.to_string()
            )),
            Fragment::AndOr { x, y, z } => Ok(format!(
                "{} NOTIF {} ELSE {} ENDIF",
                self.visit_ast(ctx, x)?,
                self.visit_ast(ctx, y)?,
                self.visit_ast(ctx, z)?
            )),
            Fragment::AndV { x, y } => Ok(format!(
                "{} {}",
                self.visit_ast(ctx, x)?,
                self.visit_ast(ctx, y)?
            )),
            Fragment::AndB { x, y } => Ok(format!(
                "{} {} BOOLAND",
                self.visit_ast(ctx, x)?,
                self.visit_ast(ctx, y)?
            )),
            Fragment::OrB { x, z } => Ok(format!(
                "{} {} BOOLOR",
                self.visit_ast(ctx, x)?,
                self.visit_ast(ctx, z)?
            )),
            Fragment::OrC { x, z } => Ok(format!(
                "{} NOTIF {} ENDIF",
                self.visit_ast(ctx, x)?,
                self.visit_ast(ctx, z)?
            )),
            Fragment::OrD { x, z } => Ok(format!(
                "{} IFDUP NOTIF {} ENDIF",
                self.visit_ast(ctx, x)?,
                self.visit_ast(ctx, z)?
            )),
            Fragment::OrI { x, z } => Ok(format!(
                "IF {} ELSE {} ENDIF",
                self.visit_ast(ctx, x)?,
                self.visit_ast(ctx, z)?
            )),
            Fragment::Thresh { k, xs } => {
                // [X1] [X2] ADD ... [Xn] ADD ... <k> EQUAL

                let mut script = String::new();
                for x in xs {
                    script.push_str(&self.visit_ast(ctx, x)?);
                    script.push_str(" ADD ");
                }
                script.push_str(&format!("<{}> EQUAL", k));
                Ok(script)
            }
            Fragment::Multi { k, keys } => {
                // <k> <key1> ... <keyn> <n> CHECKMULTISIG

                let mut script = String::new();
                for key in keys {
                    script.push_str(key);
                    script.push_str(" ");
                }
                script.push_str(&format!("<{}> CHECKMULTISIG", k));
                Ok(script)
            }
            Fragment::MultiA { k, keys } => {
                // <key1> CHECKSIG <key2> CHECKSIGADD ... <keyn> CHECKSIGADD <k> NUMEQUAL

                let mut script = String::new();
                for key in keys {
                    script.push_str(key);
                    script.push_str(" CHECKSIG ADD ");
                }
                script.push_str(&format!("<{}> NUMEQUAL", k));
                Ok(script)
            }
            Fragment::Identity { identity_type, x } => match identity_type {
                crate::parser::IdentityType::A => Ok(format!(
                    "TOALTSTACK {} FROMALTSTACK",
                    self.visit_ast(ctx, x)?
                )),
                crate::parser::IdentityType::S => Ok(format!("SWAP {}", self.visit_ast(ctx, x)?)),
                crate::parser::IdentityType::C => {
                    Ok(format!("{} CHECKSIG", self.visit_ast(ctx, x)?))
                }
                crate::parser::IdentityType::D => {
                    Ok(format!("DUP IF {} ENDIF", self.visit_ast(ctx, x)?))
                }
                crate::parser::IdentityType::V => Ok(format!("{} VERIFY", self.visit_ast(ctx, x)?)),
                crate::parser::IdentityType::J => Ok(format!(
                    "SIZE 0NOTEQUAL IF {} ENDIF",
                    self.visit_ast(ctx, x)?
                )),
                crate::parser::IdentityType::N => {
                    Ok(format!("{} 0NOTEQUAL", self.visit_ast(ctx, x)?))
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::parser;

    use super::*;

    #[test]
    fn test_translator_visitor() {
        // let simple_script = "or_b(pk(020202020202020202020202020202020202020202020202020202020202020202),pk(030303030303030303030303030303030303030303030303030303030303030303))";

        let script = "or_d(pk(pubkey1),and_v(v:pk(pubkey2),older(52560)))";

        let mut ctx = Context::new(script);
        let ast = parser::parse(&mut ctx).unwrap();

        let mut visitor = TranslatorVisitor::new();
        let result = visitor.visit_ast(&mut ctx, &ast).unwrap();

        assert_eq!(
            result,
            "<pubkey1> CHECKSIG IFDUP NOTIF <pubkey2> CHECKSIG VERIFY <52560> CHECKSEQUENCEVERIFY ENDIF"
        );
    }
}
