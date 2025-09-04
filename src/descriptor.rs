use core::marker::PhantomData;

use crate::parser::{AST, ASTVisitor, Fragment, ParserContext, Position};

/// Script descriptor
#[cfg_attr(feature = "debug", derive(Debug))]
#[derive(Clone, PartialEq)]
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

pub struct InvalidDescriptor<'a>(&'a str);

impl<'a> TryFrom<&'a str> for Descriptor {
    type Error = InvalidDescriptor<'a>;
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        match value {
            "pkh" => Ok(Descriptor::Pkh),
            "sh" => Ok(Descriptor::Sh),
            "wpkh" => Ok(Descriptor::Wpkh),
            "wsh" => Ok(Descriptor::Wsh),
            "tr" => Ok(Descriptor::Tr),
            _ => Err(InvalidDescriptor(value)),
        }
    }
}

pub struct DescriptorValidator<'a> {
    phantom: PhantomData<&'a ()>,
}

impl<'a> DescriptorValidator<'a> {
    #[inline]
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

#[cfg_attr(feature = "debug", derive(Debug))]
pub enum DescriptorVisitorError {
    InvalidFragmentForDescriptor {
        position: Position,
        expected: Descriptor,
        found: Descriptor,
    },
    PublicKeyNotCompressed {
        position: Position,
    },
}

impl<'a> ASTVisitor<'a, ()> for DescriptorValidator<'a> {
    type Error = DescriptorVisitorError;

    fn visit_ast(&mut self, ctx: &ParserContext<'a>, node: &AST<'a>) -> Result<(), Self::Error> {
        match &node.fragment {
            Fragment::Descriptor { descriptor, inner } => {
                self.visit_ast_by_index(ctx, *inner)?;
            }

            Fragment::False => {}
            Fragment::True => {}
            Fragment::PkK { key } | Fragment::PkH { key } => match &ctx.descriptor() {
                Descriptor::Bare => {}
                Descriptor::Pkh => {}
                Descriptor::Sh => {}
                Descriptor::Wpkh | Descriptor::Wsh => {
                    if !key.is_compressed() {
                        return Err(DescriptorVisitorError::PublicKeyNotCompressed {
                            position: node.position,
                        });
                    }
                }
                Descriptor::Tr => {}
            },
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
                if ctx.descriptor() != Descriptor::Wsh {
                    return Err(DescriptorVisitorError::InvalidFragmentForDescriptor {
                        position: node.position,
                        expected: Descriptor::Wsh,
                        found: ctx.descriptor(),
                    });
                }
            }
            Fragment::MultiA { k, keys } => {
                // Tapscript only
                if ctx.descriptor() != Descriptor::Tr {
                    return Err(DescriptorVisitorError::InvalidFragmentForDescriptor {
                        position: node.position,
                        expected: Descriptor::Tr,
                        found: ctx.descriptor(),
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
