use crate::parser::{AST, ASTVisitor, Fragment, ParserContext, Position};

/// Script descriptor
#[derive(Clone, PartialEq)]
#[repr(u8)]
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

pub struct InvalidDescriptor;

impl<'a> TryFrom<&'a str> for Descriptor {
    type Error = InvalidDescriptor;
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        match value {
            "pkh" => Ok(Descriptor::Pkh),
            "sh" => Ok(Descriptor::Sh),
            "wpkh" => Ok(Descriptor::Wpkh),
            "wsh" => Ok(Descriptor::Wsh),
            "tr" => Ok(Descriptor::Tr),
            _ => Err(InvalidDescriptor),
        }
    }
}

#[cfg(feature = "debug")]
impl core::fmt::Debug for Descriptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Descriptor::Bare => write!(f, "bare"),
            Descriptor::Pkh => write!(f, "pkh"),
            Descriptor::Sh => write!(f, "sh"),
            Descriptor::Wpkh => write!(f, "wpkh"),
            Descriptor::Wsh => write!(f, "wsh"),
            Descriptor::Tr => write!(f, "tr"),
        }
    }
}

pub struct DescriptorValidator {}

impl DescriptorValidator {
    #[inline]
    pub const fn new() -> Self {
        Self {}
    }

    /// Validate the descriptor structure
    /// Not using a Visitor pattern because it's not needed for the current use case.
    pub fn validate(&self, ctx: &ParserContext) -> Result<(), DescriptorVisitorError> {
        let descriptor = ctx.descriptor();
        for ele in ctx.nodes.iter() {
            match &ele.fragment {
                Fragment::PkK { key } | Fragment::PkH { key } => {
                    match &descriptor {
                        Descriptor::Bare => {}
                        Descriptor::Pkh => {}
                        Descriptor::Sh => {}
                        Descriptor::Wpkh | Descriptor::Wsh => {
                            if !key.is_compressed() {
                                return Err(DescriptorVisitorError::PublicKeyNotCompressed {
                                    position: ele.position,
                                });
                            }
                        }
                        Descriptor::Tr => {}
                    }
                }
                Fragment::Multi { keys, .. } => {
                    // (P2WSH only)
                    if descriptor != Descriptor::Wsh {
                        return Err(DescriptorVisitorError::InvalidFragmentForDescriptor {
                            position: ele.position,
                            expected: Descriptor::Wsh,
                            found: descriptor,
                        });
                    }
                }
                Fragment::MultiA { keys, .. } => {
                    // Tapscript only
                    if descriptor != Descriptor::Tr {
                        return Err(DescriptorVisitorError::InvalidFragmentForDescriptor {
                            position: ele.position,
                            expected: Descriptor::Tr,
                            found: descriptor,
                        });
                    }
                }
                Fragment::RawPkH { key } => {
   
                    match &descriptor {
                        Descriptor::Wpkh => {
                            if !key.is_compressed() {
                                return Err(DescriptorVisitorError::PublicKeyNotCompressed {
                                    position: ele.position,
                                });
                            }
                        }
                        _ => {}
                    }
                }
                _ => {
                    continue;
                }
            }
        }
        Ok(())
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