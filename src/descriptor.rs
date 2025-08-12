use crate::{
    model::KeyRegistry,
    parser::{AST, ASTVisitor, Fragment, ParserContext, Position},
};

/// Script descriptor
#[derive(Debug, Clone, PartialEq)]
pub enum Descriptor {
    /// A raw scriptpubkey (including pay-to-pubkey) under Legacy context
    Bare,

    /// Pay-to-PubKey-Hash
    Pkh,
    /// Pay-to-ScriptHash(includes nested wsh/wpkh/sorted multi)
    Sh,

    /// Pay-to-Witness-PubKey-Hash
    Wpkh,
    /// Pay-to-Witness-ScriptHash with Segwitv0 context
    Wsh,

    /// Pay-to-Taproot
    Tr,
}

impl Default for Descriptor {
    #[inline]
    fn default() -> Self {
        Descriptor::Bare
    }
}

impl Descriptor {
    #[inline]
    pub fn from_fragment(fragment: &str) -> Self {
        match fragment {
            "pkh" => Descriptor::Pkh,
            "sh" => Descriptor::Sh,
            "wpkh" => Descriptor::Wpkh,
            "wsh" => Descriptor::Wsh,
            "tr" => Descriptor::Tr,
            _ => Descriptor::Bare,
        }
    }
}

pub struct DescriptorValidator<'a, 'b> {
    script_builder: &'b KeyRegistry<'a>,
    descriptor: Descriptor,
}

impl<'a, 'b> DescriptorValidator<'a, 'b> {
    #[inline]
    pub fn new(script_builder: &'b KeyRegistry<'a>) -> Self {
        Self {
            script_builder,
            descriptor: Descriptor::default(),
        }
    }
}

#[derive(Debug)]
pub enum DescriptorVisitorError<'a> {
    KeyNotFound {
        position: Position,
        key: &'a str,
    },
    InvalidFragmentForDescriptor {
        position: Position,
        expected: Descriptor,
        found: Descriptor,
    },
    InvalidPublicKeyForDescriptor {
        position: Position,
        label: &'a str,
        reason: &'static str,
    },
}

impl<'a, 'b> ASTVisitor<'a, ()> for DescriptorValidator<'a, 'b> {
    type Error = DescriptorVisitorError<'a>;

    fn visit_ast(&mut self, ctx: &ParserContext<'a>, node: &AST<'a>) -> Result<(), Self::Error> {
        match &node.fragment {
            Fragment::Descriptor { descriptor, inner } => {
                self.descriptor = descriptor.clone();
                self.visit_ast_by_index(ctx, *inner)?;
            }

            Fragment::False => {}
            Fragment::True => {}
            Fragment::PkK { key } | Fragment::PkH { key } => {
                let public_key = self.script_builder.get_key(key).ok_or(
                    DescriptorVisitorError::KeyNotFound {
                        position: node.position,
                        key: key,
                    },
                )?;

                match &self.descriptor {
                    Descriptor::Bare => {}
                    Descriptor::Pkh => {}
                    Descriptor::Sh => {}
                    Descriptor::Wpkh | Descriptor::Wsh => {
                        if !public_key.compressed {
                            return Err(DescriptorVisitorError::InvalidPublicKeyForDescriptor {
                                position: node.position,
                                label: key,
                                reason: "public key must be compressed",
                            });
                        }
                    }
                    Descriptor::Tr => {}
                }
            }
            Fragment::Older { n } => {}
            Fragment::After { n } => {}
            Fragment::Sha256 { h } => {}
            Fragment::Hash256 { h } => {}
            Fragment::Ripemd160 { h } => {}
            Fragment::Hash160 { h } => {}
            Fragment::AndOr { x, y, z } => {
                self.visit_ast_by_index(ctx, *x)?;
                self.visit_ast_by_index(ctx, *y)?;
                self.visit_ast_by_index(ctx, *z)?;
            }
            Fragment::AndV { x, y } => {
                self.visit_ast_by_index(ctx, *x)?;
                self.visit_ast_by_index(ctx, *y)?;
            }
            Fragment::AndB { x, y } => {
                self.visit_ast_by_index(ctx, *x)?;
                self.visit_ast_by_index(ctx, *y)?;
            }
            Fragment::OrB { x, z } => {
                self.visit_ast_by_index(ctx, *x)?;
                self.visit_ast_by_index(ctx, *z)?;
            }
            Fragment::OrC { x, z } => {
                self.visit_ast_by_index(ctx, *x)?;
                self.visit_ast_by_index(ctx, *z)?;
            }
            Fragment::OrD { x, z } => {
                self.visit_ast_by_index(ctx, *x)?;
                self.visit_ast_by_index(ctx, *z)?;
            }
            Fragment::OrI { x, z } => {
                self.visit_ast_by_index(ctx, *x)?;
                self.visit_ast_by_index(ctx, *z)?;
            }
            Fragment::Thresh { k, xs } => {
                for x in xs {
                    self.visit_ast_by_index(ctx, *x)?;
                }
            }
            Fragment::Multi { k, keys } => {
                // (P2WSH only)
                if self.descriptor != Descriptor::Wsh {
                    return Err(DescriptorVisitorError::InvalidFragmentForDescriptor {
                        position: node.position,
                        expected: Descriptor::Wsh,
                        found: self.descriptor.clone(),
                    });
                }
            }
            Fragment::MultiA { k, keys } => {
                // Tapscript only
                if self.descriptor != Descriptor::Tr {
                    return Err(DescriptorVisitorError::InvalidFragmentForDescriptor {
                        position: node.position,
                        expected: Descriptor::Tr,
                        found: self.descriptor.clone(),
                    });
                }
            }
            Fragment::Identity { identity_type, x } => {
                self.visit_ast_by_index(ctx, *x)?;
            }
        }
        Ok(())
    }
}
