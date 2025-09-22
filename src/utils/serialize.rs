use alloc::{format, string::String};

use crate::parser::{AST, Fragment, ParserContext};

/// Serializer for Miniscript descriptors.
pub struct Serializer {
    output: String,
}

impl Serializer {
    pub const fn new() -> Self {
        Self {
            output: String::new(),
        }
    }

    pub fn serialize(&mut self, ctx: &ParserContext) -> String {
        self.output.clear();
        self.serialize_node(ctx, ctx.get_root());
        self.output.clone()
    }

    fn serialize_node(&mut self, ctx: &ParserContext, ast: &AST) {
        match &ast.fragment {
            Fragment::False => {
                self.output.push_str("0");
            }
            Fragment::True => {
                self.output.push_str("1");
            }
            Fragment::PkK { key } => {
                self.output.push_str(&format!("pk_k({:?})", key));
            }
            Fragment::PkH { key } => {
                self.output.push_str(&format!("pk_h({:?})", key));
            }
            Fragment::Older { n } => {
                self.output.push_str(&format!("older({})", n));
            }
            Fragment::After { n } => {
                self.output.push_str(&format!("after({})", n));
            }
            Fragment::Sha256 { h } => {
                self.output.push_str(&format!("sha256({:?})", h));
            }
            Fragment::Hash256 { h } => {
                self.output.push_str(&format!("hash256({:?})", h));
            }
            Fragment::Ripemd160 { h } => {
                self.output.push_str(&format!("ripemd160({:?})", h));
            }
            Fragment::Hash160 { h } => {
                self.output.push_str(&format!("hash160({:?})", h));
            }
            Fragment::AndOr { x, y, z } => {
                self.output.push_str("andor(");
                self.serialize_node(ctx, ctx.get_node(*x));
                self.output.push_str(",");
                self.serialize_node(ctx, ctx.get_node(*y));
                self.output.push_str(",");
                self.serialize_node(ctx, ctx.get_node(*z));
                self.output.push_str(")");
            }
            Fragment::AndV { x, y } => {
                self.output.push_str("and_v(");
                self.serialize_node(ctx, ctx.get_node(*x));
                self.output.push_str(",");
                self.serialize_node(ctx, ctx.get_node(*y));
                self.output.push_str(")");
            }
            Fragment::AndB { x, y } => {
                self.output.push_str("and_b(");
                self.serialize_node(ctx, ctx.get_node(*x));
                self.output.push_str(",");
                self.serialize_node(ctx, ctx.get_node(*y));
                self.output.push_str(")");
            }
            Fragment::OrB { x, z } => {
                self.output.push_str("or_b(");
                self.serialize_node(ctx, ctx.get_node(*x));
                self.output.push_str(",");
                self.serialize_node(ctx, ctx.get_node(*z));
                self.output.push_str(")");
            }
            Fragment::OrC { x, z } => {
                self.output.push_str("or_c(");
                self.serialize_node(ctx, ctx.get_node(*x));
                self.output.push_str(",");
                self.serialize_node(ctx, ctx.get_node(*z));
                self.output.push_str(")");
            }
            Fragment::OrD { x, z } => {
                self.output.push_str("or_d(");
                self.serialize_node(ctx, ctx.get_node(*x));
                self.output.push_str(",");
                self.serialize_node(ctx, ctx.get_node(*z));
                self.output.push_str(")");
            }
            Fragment::OrI { x, z } => {
                self.output.push_str("or_i(");
                self.serialize_node(ctx, ctx.get_node(*x));
                self.output.push_str(",");
                self.serialize_node(ctx, ctx.get_node(*z));
                self.output.push_str(")");
            }
            Fragment::Thresh { k, xs } => {
                self.output.push_str(&format!("thresh({}", k));
                for x in xs {
                    self.output.push_str(",");
                    self.serialize_node(ctx, ctx.get_node(*x));
                }
                self.output.push_str(")");
            }
            Fragment::Multi { k, keys } => {
                self.output.push_str(&format!("multi({}", k));
                for key in keys {
                    self.output.push_str(&format!(",{:?}", key));
                }
                self.output.push_str(")");
            }
            Fragment::MultiA { k, keys } => {
                // keys joined by comma
                self.output.push_str(&format!("multi_a({}", k));
                for key in keys {
                    self.output.push_str(&format!(",{:?}", key));
                }
                self.output.push_str(")");
            }
            Fragment::Identity { identity_type, x } => {
                self.output.push_str(&format!("{:?}", identity_type));

                // if the inner node is an identity, do not add a colon
                match &ctx.get_node(*x).fragment {
                    Fragment::Identity { .. } => {}
                    _ => {
                        self.output.push_str(":");
                    }
                }
                self.serialize_node(ctx, ctx.get_node(*x));
            }
            Fragment::Descriptor { descriptor, inner } => {
                self.output.push_str(&format!("{:?}(", descriptor));
                self.serialize_node(ctx, ctx.get_node(*inner));
                self.output.push_str(")");
            }
            Fragment::RawPkH { key } => {
                self.output.push_str(&format!("{:?}", key));
            }
            Fragment::RawTr { key, inner } => {
                self.output.push_str(&format!("{:?}", key));
                if let Some(inner) = inner {
                    self.output.push_str(",");
                    self.serialize_node(ctx, ctx.get_node(*inner));

                }
            }
        }
    }
}
