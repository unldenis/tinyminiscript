use core::marker::PhantomData;

use bitcoin::{
    Address, Network, PubkeyHash, ScriptBuf, key::ParsePublicKeyError, opcodes, script::Builder,
};

use crate::{
    descriptor::Descriptor,
    parser::{AST, Fragment, ParserContext, Position},
};

#[cfg_attr(feature = "debug", derive(Debug))]
pub enum ScriptBuilderError<'a> {
    InvalidKeyForDescriptor {
        position: Position,
        key: &'a str,
        inner: ParsePublicKeyError,
    },
    InvalidXOnlyKeyForDescriptor {
        position: Position,
        key: &'a str,
    },
    NonDefiniteKey(alloc::string::String),

    NoAddressForm,
}

pub(crate) fn build_script<'a>(
    ctx: &ParserContext<'a>,
) -> Result<ScriptBuf, ScriptBuilderError<'a>> {
    let mut script_builder = ScriptBuilder::new();

    let mut builder = Builder::new();
    builder = script_builder.build_fragment(ctx, ctx.get_root(), builder)?;
    Ok(builder.into_script())
}

pub(crate) fn build_address<'a>(
    ctx: &ParserContext<'a>,
    network: Network,
) -> Result<Address, ScriptBuilderError<'a>> {
    match ctx.descriptor() {
        Descriptor::Bare => Err(ScriptBuilderError::NoAddressForm),
        Descriptor::Pkh => {
            let mut key = None;
            ctx.iterate_keys(|k| key = Some(k.clone()));
            let key = key.expect("One key is always present");
            let key = key
                .as_definite_key()
                .ok_or_else(|| ScriptBuilderError::NonDefiniteKey(key.identifier()))?;

            let key = bitcoin::PublicKey::from_slice(&key.to_bytes()).expect("Valid key");
            Ok(Address::p2pkh(key, network))
        }
        Descriptor::Wpkh => {
            let mut key = None;
            ctx.iterate_keys(|k| key = Some(k.clone()));
            let key = key.expect("One key is always present");
            let key = key
                .as_definite_key()
                .ok_or_else(|| ScriptBuilderError::NonDefiniteKey(key.identifier()))?;

            let key = bitcoin::CompressedPublicKey::from_slice(&key.to_bytes()).expect("Valid key");

            if ctx.is_wrapped() {
                Ok(Address::p2shwpkh(&key, network))
            } else {
                Ok(Address::p2wpkh(&key, network))
            }
        }
        Descriptor::Sh => {
            let script = build_script(ctx)?;
            Ok(Address::p2sh(script.as_script(), network).expect("Rules validated by parser"))
        }
        Descriptor::Wsh => {
            let script = build_script(ctx)?;
            if ctx.is_wrapped() {
                Ok(Address::p2shwsh(script.as_script(), network))
            } else {
                Ok(Address::p2wsh(script.as_script(), network))
            }
        }
        Descriptor::Tr => unimplemented!(),
    }
}

struct ScriptBuilder<'a> {
    phantom: PhantomData<&'a ()>,
    descriptor: Descriptor,
}

impl<'a> ScriptBuilder<'a> {
    fn new() -> Self {
        Self {
            phantom: PhantomData,
            descriptor: Descriptor::default(),
        }
    }

    fn build_fragment(
        &mut self,
        ctx: &ParserContext<'a>,
        ast: &AST,
        mut builder: Builder,
    ) -> Result<Builder, ScriptBuilderError<'a>> {
        match &ast.fragment {
            Fragment::False => {
                builder = builder.push_opcode(opcodes::OP_FALSE);
                Ok(builder)
            }
            Fragment::True => {
                builder = builder.push_opcode(opcodes::OP_TRUE);
                Ok(builder)
            }
            Fragment::PkK { key } => {
                let key = match key.as_definite_key() {
                    Some(k) => k,
                    None => return Err(ScriptBuilderError::NonDefiniteKey(key.identifier())),
                };
                builder = key.push_to_script(builder);
                Ok(builder)
            }
            Fragment::PkH { key } => {
                let key = match key.as_definite_key() {
                    Some(k) => k,
                    None => return Err(ScriptBuilderError::NonDefiniteKey(key.identifier())),
                };
                let hash: PubkeyHash = key.pubkey_hash();

                builder = builder
                    .push_opcode(opcodes::all::OP_DUP)
                    .push_opcode(opcodes::all::OP_HASH160)
                    .push_slice(&hash)
                    .push_opcode(opcodes::all::OP_EQUALVERIFY);
                Ok(builder)
            }
            Fragment::Older { n } => {
                builder = builder
                    .push_int(*n as i64)
                    .push_opcode(opcodes::all::OP_CSV);
                Ok(builder)
            }
            Fragment::After { n } => {
                builder = builder
                    .push_int(*n as i64)
                    .push_opcode(opcodes::all::OP_CLTV);
                Ok(builder)
            }
            Fragment::Sha256 { h } => {
                builder = builder
                    .push_opcode(opcodes::all::OP_SIZE)
                    .push_int(32)
                    .push_opcode(opcodes::all::OP_EQUALVERIFY)
                    .push_opcode(opcodes::all::OP_SHA256)
                    .push_slice(h)
                    .push_opcode(opcodes::all::OP_EQUAL);
                Ok(builder)
            }
            Fragment::Hash256 { h } => {
                builder = builder
                    .push_opcode(opcodes::all::OP_SIZE)
                    .push_int(32)
                    .push_opcode(opcodes::all::OP_EQUALVERIFY)
                    .push_opcode(opcodes::all::OP_HASH256)
                    .push_slice(h)
                    .push_opcode(opcodes::all::OP_EQUAL);
                Ok(builder)
            }
            Fragment::Ripemd160 { h } => {
                builder = builder
                    .push_opcode(opcodes::all::OP_SIZE)
                    .push_int(32)
                    .push_opcode(opcodes::all::OP_EQUALVERIFY)
                    .push_opcode(opcodes::all::OP_RIPEMD160)
                    .push_slice(h)
                    .push_opcode(opcodes::all::OP_EQUAL);
                Ok(builder)
            }
            Fragment::Hash160 { h } => {
                builder = builder
                    .push_opcode(opcodes::all::OP_SIZE)
                    .push_int(32)
                    .push_opcode(opcodes::all::OP_EQUALVERIFY)
                    .push_opcode(opcodes::all::OP_HASH160)
                    .push_slice(h)
                    .push_opcode(opcodes::all::OP_EQUAL);
                Ok(builder)
            }
            Fragment::AndOr { x, y, z } => {
                let builder = self.build_fragment(ctx, ctx.get_node(*x), builder)?;
                let builder = builder.push_opcode(opcodes::all::OP_NOTIF);
                let builder = self.build_fragment(ctx, ctx.get_node(*z), builder)?;
                let builder = builder.push_opcode(opcodes::all::OP_ELSE);
                let builder = self.build_fragment(ctx, ctx.get_node(*y), builder)?;
                let builder = builder.push_opcode(opcodes::all::OP_ENDIF);
                Ok(builder)
            }
            Fragment::AndV { x, y } => {
                let builder = self.build_fragment(ctx, ctx.get_node(*x), builder)?;
                let builder = self.build_fragment(ctx, ctx.get_node(*y), builder)?;
                Ok(builder)
            }
            Fragment::AndB { x, y } => {
                let builder = self.build_fragment(ctx, ctx.get_node(*x), builder)?;
                let builder = self.build_fragment(ctx, ctx.get_node(*y), builder)?;
                let builder = builder.push_opcode(opcodes::all::OP_BOOLAND);
                Ok(builder)
            }
            Fragment::OrB { x, z } => {
                let builder = self.build_fragment(ctx, ctx.get_node(*x), builder)?;
                let builder = self.build_fragment(ctx, ctx.get_node(*z), builder)?;
                let builder = builder.push_opcode(opcodes::all::OP_BOOLOR);
                Ok(builder)
            }
            Fragment::OrC { x, z } => {
                let builder = self.build_fragment(ctx, ctx.get_node(*x), builder)?;
                let builder = builder.push_opcode(opcodes::all::OP_NOTIF);
                let builder = self.build_fragment(ctx, ctx.get_node(*z), builder)?;
                let builder = builder.push_opcode(opcodes::all::OP_ENDIF);
                Ok(builder)
            }
            Fragment::OrD { x, z } => {
                let builder = self.build_fragment(ctx, ctx.get_node(*x), builder)?;
                let builder = builder.push_opcode(opcodes::all::OP_IFDUP);
                let builder = builder.push_opcode(opcodes::all::OP_NOTIF);
                let builder = self.build_fragment(ctx, ctx.get_node(*z), builder)?;
                let builder = builder.push_opcode(opcodes::all::OP_ENDIF);
                Ok(builder)
            }
            Fragment::OrI { x, z } => {
                let builder = builder.push_opcode(opcodes::all::OP_IF);
                let builder = self.build_fragment(ctx, ctx.get_node(*x), builder)?;
                let builder = builder.push_opcode(opcodes::all::OP_ELSE);
                let builder = self.build_fragment(ctx, ctx.get_node(*z), builder)?;
                let builder = builder.push_opcode(opcodes::all::OP_ENDIF);
                Ok(builder)
            }
            Fragment::Thresh { k, xs } => {
                // must be at least one key
                builder = self.build_fragment(ctx, ctx.get_node(xs[0]), builder)?;

                let mut builder = builder;
                for x in xs.iter().skip(1) {
                    builder = self.build_fragment(ctx, ctx.get_node(*x), builder)?;
                    builder = builder.push_opcode(opcodes::all::OP_ADD);
                }
                builder = builder.push_int(*k as i64);
                builder = builder.push_opcode(opcodes::all::OP_EQUAL);
                Ok(builder)
            }
            Fragment::Multi { k, keys } => {
                let mut builder = builder.push_int(*k as i64);
                for key in keys {
                    // Multi only supports public keys
                    let key = match key.as_definite_key() {
                        Some(k) => k,
                        None => return Err(ScriptBuilderError::NonDefiniteKey(key.identifier())),
                    };
                    builder = key.push_to_script(builder);
                }
                builder = builder.push_int(keys.len() as i64);
                builder = builder.push_opcode(opcodes::all::OP_CHECKMULTISIG);
                Ok(builder)
            }
            Fragment::MultiA { k, keys } => {
                let mut builder = builder;
                for key in keys {
                    let key = match key.as_definite_key() {
                        Some(k) => k,
                        None => return Err(ScriptBuilderError::NonDefiniteKey(key.identifier())),
                    };
                    builder = key.push_to_script(builder);

                    builder = builder.push_opcode(opcodes::all::OP_CHECKSIG);
                    builder = builder.push_opcode(opcodes::all::OP_ADD);
                }
                builder = builder.push_int(*k as i64);
                builder = builder.push_opcode(opcodes::all::OP_NUMEQUAL);
                Ok(builder)
            }
            Fragment::Identity { identity_type, x } => match identity_type {
                crate::parser::IdentityType::A => {
                    let builder = builder.push_opcode(opcodes::all::OP_TOALTSTACK);
                    let builder = self.build_fragment(ctx, ctx.get_node(*x), builder)?;
                    let builder = builder.push_opcode(opcodes::all::OP_FROMALTSTACK);
                    Ok(builder)
                }
                crate::parser::IdentityType::S => {
                    let builder = builder.push_opcode(opcodes::all::OP_SWAP);
                    let builder = self.build_fragment(ctx, ctx.get_node(*x), builder)?;
                    Ok(builder)
                }
                crate::parser::IdentityType::C => {
                    let builder = self.build_fragment(ctx, ctx.get_node(*x), builder)?;
                    let builder = builder.push_opcode(opcodes::all::OP_CHECKSIG);
                    Ok(builder)
                }
                crate::parser::IdentityType::D => {
                    let builder = builder.push_opcode(opcodes::all::OP_DUP);
                    let builder = builder.push_opcode(opcodes::all::OP_IF);
                    let builder = self.build_fragment(ctx, ctx.get_node(*x), builder)?;
                    let builder = builder.push_opcode(opcodes::all::OP_ENDIF);
                    Ok(builder)
                }
                crate::parser::IdentityType::V => {
                    let builder = self.build_fragment(ctx, ctx.get_node(*x), builder)?;
                    let builder = builder.push_verify();
                    Ok(builder)
                }
                crate::parser::IdentityType::J => {
                    let builder = builder.push_opcode(opcodes::all::OP_SIZE);
                    let builder = builder.push_opcode(opcodes::all::OP_0NOTEQUAL);
                    let builder = builder.push_opcode(opcodes::all::OP_IF);
                    let builder = self.build_fragment(ctx, ctx.get_node(*x), builder)?;
                    let builder = builder.push_opcode(opcodes::all::OP_ENDIF);
                    Ok(builder)
                }
                crate::parser::IdentityType::N => {
                    let builder = self.build_fragment(ctx, ctx.get_node(*x), builder)?;
                    let builder = builder.push_opcode(opcodes::all::OP_0NOTEQUAL);
                    Ok(builder)
                }
            },
            Fragment::Descriptor { descriptor, inner } => {
                // set descriptor
                self.descriptor = descriptor.clone();

                let builder = self.build_fragment(ctx, ctx.get_node(*inner), builder)?;
                Ok(builder)
            }
            Fragment::RawPkH { key } => {
                let key = match key.as_definite_key() {
                    Some(k) => k,
                    None => return Err(ScriptBuilderError::NonDefiniteKey(key.identifier())),
                };
                let hash: PubkeyHash = key.pubkey_hash();

                builder = builder
                    .push_opcode(opcodes::all::OP_DUP)
                    .push_opcode(opcodes::all::OP_HASH160)
                    .push_slice(&hash)
                    .push_opcode(opcodes::all::OP_EQUALVERIFY)
                    .push_opcode(opcodes::all::OP_CHECKSIG);
                Ok(builder)
            }
            Fragment::RawTr { key, inner } => {
                if let Some(inner) = inner {
                    let builder = self.build_fragment(ctx, ctx.get_node(*inner), builder)?;
                    Ok(builder)
                } else {
                    panic!("Taproot script without inner is not supported");
                }
            },
        }
    }
}
