use alloc::collections::BTreeMap;
use bitcoin::{
    PublicKey, ScriptBuf, opcodes,
    script::{Builder, PushBytesBuf},
};

use crate::parser::{AST, Fragment, ParserContext, Position};

#[derive(Debug)]
pub struct ScriptBuilder<'a> {
    keys: BTreeMap<&'a str, PublicKey>,
    hashes: BTreeMap<&'a str, PushBytesBuf>,
}

impl<'a> Default for ScriptBuilder<'a> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> ScriptBuilder<'a> {
    #[inline]
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
            hashes: BTreeMap::new(),
        }
    }

    #[inline]
    pub fn add_key(&mut self, key: &'a str, public_key: PublicKey) {
        self.keys.insert(key, public_key);
    }

    #[inline]
    pub fn add_hash(&mut self, hash: &'a str, data: PushBytesBuf) {
        self.hashes.insert(hash, data);
    }
}

#[derive(Debug)]
pub enum ScriptBuilderError<'a> {
    KeyNotFound { position: Position, key: &'a str },
    HashNotFound { position: Position, hash: &'a str },
}

#[inline]
pub fn build_script<'a>(
    script_builder: &ScriptBuilder<'a>,
    ctx: &ParserContext<'a>,
) -> Result<ScriptBuf, ScriptBuilderError<'a>> {
    let mut builder = Builder::new();
    builder = build_fragment(script_builder, ctx, ctx.get_root(), builder)?;
    Ok(builder.into_script())
}

fn build_fragment<'a>(
    script_builder: &ScriptBuilder<'a>,
    ctx: &ParserContext<'a>,
    ast: &AST<'a>,
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
            let public_key =
                script_builder
                    .keys
                    .get(key)
                    .ok_or(ScriptBuilderError::KeyNotFound {
                        position: ast.position,
                        key,
                    })?;
            builder = builder.push_key(public_key);
            Ok(builder)
        }
        Fragment::PkH { key } => {
            let public_key =
                script_builder
                    .keys
                    .get(key)
                    .ok_or(ScriptBuilderError::KeyNotFound {
                        position: ast.position,
                        key,
                    })?;
            builder = builder
                .push_opcode(opcodes::all::OP_DUP)
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(public_key.pubkey_hash())
                .push_opcode(opcodes::all::OP_EQUALVERIFY);
            Ok(builder)
        }
        Fragment::Older { n } => {
            builder = builder.push_int(*n).push_opcode(opcodes::all::OP_CSV);
            Ok(builder)
        }
        Fragment::After { n } => {
            builder = builder.push_int(*n).push_opcode(opcodes::all::OP_CLTV);
            Ok(builder)
        }
        Fragment::Sha256 { h } => {
            let hash = script_builder
                .hashes
                .get(h)
                .ok_or(ScriptBuilderError::HashNotFound {
                    position: ast.position,
                    hash: h,
                })?;

            builder = builder
                .push_opcode(opcodes::all::OP_SIZE)
                .push_int(32)
                .push_opcode(opcodes::all::OP_EQUALVERIFY)
                .push_opcode(opcodes::all::OP_SHA256)
                .push_slice(hash)
                .push_opcode(opcodes::all::OP_EQUAL);
            Ok(builder)
        }
        Fragment::Hash256 { h } => {
            let hash = script_builder
                .hashes
                .get(h)
                .ok_or(ScriptBuilderError::HashNotFound {
                    position: ast.position,
                    hash: h,
                })?;
            builder = builder
                .push_opcode(opcodes::all::OP_SIZE)
                .push_int(32)
                .push_opcode(opcodes::all::OP_EQUALVERIFY)
                .push_opcode(opcodes::all::OP_HASH256)
                .push_slice(hash)
                .push_opcode(opcodes::all::OP_EQUAL);
            Ok(builder)
        }
        Fragment::Ripemd160 { h } => {
            let hash = script_builder
                .hashes
                .get(h)
                .ok_or(ScriptBuilderError::HashNotFound {
                    position: ast.position,
                    hash: h,
                })?;
            builder = builder
                .push_opcode(opcodes::all::OP_SIZE)
                .push_int(32)
                .push_opcode(opcodes::all::OP_EQUALVERIFY)
                .push_opcode(opcodes::all::OP_RIPEMD160)
                .push_slice(hash)
                .push_opcode(opcodes::all::OP_EQUAL);
            Ok(builder)
        }
        Fragment::Hash160 { h } => {
            let hash = script_builder
                .hashes
                .get(h)
                .ok_or(ScriptBuilderError::HashNotFound {
                    position: ast.position,
                    hash: h,
                })?;
            builder = builder
                .push_opcode(opcodes::all::OP_SIZE)
                .push_int(32)
                .push_opcode(opcodes::all::OP_EQUALVERIFY)
                .push_opcode(opcodes::all::OP_HASH160)
                .push_slice(hash)
                .push_opcode(opcodes::all::OP_EQUAL);
            Ok(builder)
        }
        Fragment::AndOr { x, y, z } => {
            let builder = build_fragment(script_builder, ctx, ctx.get_node(*x), builder)?;
            let builder = builder.push_opcode(opcodes::all::OP_NOTIF);
            let builder = build_fragment(script_builder, ctx, ctx.get_node(*z), builder)?;
            let builder = builder.push_opcode(opcodes::all::OP_ELSE);
            let builder = build_fragment(script_builder, ctx, ctx.get_node(*y), builder)?;
            let builder = builder.push_opcode(opcodes::all::OP_ENDIF);
            Ok(builder)
        }
        Fragment::AndV { x, y } => {
            let builder = build_fragment(script_builder, ctx, ctx.get_node(*x), builder)?;
            let builder = build_fragment(script_builder, ctx, ctx.get_node(*y), builder)?;
            Ok(builder)
        }
        Fragment::AndB { x, y } => {
            let builder = build_fragment(script_builder, ctx, ctx.get_node(*x), builder)?;
            let builder = build_fragment(script_builder, ctx, ctx.get_node(*y), builder)?;
            let builder = builder.push_opcode(opcodes::all::OP_BOOLAND);
            Ok(builder)
        }
        Fragment::OrB { x, z } => {
            let builder = build_fragment(script_builder, ctx, ctx.get_node(*x), builder)?;
            let builder = build_fragment(script_builder, ctx, ctx.get_node(*z), builder)?;
            let builder = builder.push_opcode(opcodes::all::OP_BOOLOR);
            Ok(builder)
        }
        Fragment::OrC { x, z } => {
            let builder = build_fragment(script_builder, ctx, ctx.get_node(*x), builder)?;
            let builder = builder.push_opcode(opcodes::all::OP_NOTIF);
            let builder = build_fragment(script_builder, ctx, ctx.get_node(*z), builder)?;
            let builder = builder.push_opcode(opcodes::all::OP_ENDIF);
            Ok(builder)
        }
        Fragment::OrD { x, z } => {
            let builder = build_fragment(script_builder, ctx, ctx.get_node(*x), builder)?;
            let builder = builder.push_opcode(opcodes::all::OP_IFDUP);
            let builder = builder.push_opcode(opcodes::all::OP_NOTIF);
            let builder = build_fragment(script_builder, ctx, ctx.get_node(*z), builder)?;
            let builder = builder.push_opcode(opcodes::all::OP_ENDIF);
            Ok(builder)
        }
        Fragment::OrI { x, z } => {
            let builder = builder.push_opcode(opcodes::all::OP_IF);
            let builder = build_fragment(script_builder, ctx, ctx.get_node(*x), builder)?;
            let builder = builder.push_opcode(opcodes::all::OP_ELSE);
            let builder = build_fragment(script_builder, ctx, ctx.get_node(*z), builder)?;
            let builder = builder.push_opcode(opcodes::all::OP_ENDIF);
            Ok(builder)
        }
        Fragment::Thresh { k, xs } => {
            let mut builder = builder;
            for x in xs {
                builder = build_fragment(script_builder, ctx, ctx.get_node(*x), builder)?;
                builder = builder.push_opcode(opcodes::all::OP_ADD);
            }
            builder = builder.push_int(*k as i64);
            builder = builder.push_opcode(opcodes::all::OP_EQUAL);
            Ok(builder)
        }
        Fragment::Multi { k, keys } => {
            let mut builder = builder.push_int(*k as i64);
            for key in keys {
                let public_key =
                    script_builder
                        .keys
                        .get(key)
                        .ok_or(ScriptBuilderError::KeyNotFound {
                            position: ast.position,
                            key,
                        })?;
                builder = builder.push_key(public_key);
            }
            builder = builder.push_int(keys.len() as i64);
            builder = builder.push_opcode(opcodes::all::OP_CHECKMULTISIG);
            Ok(builder)
        }
        Fragment::MultiA { k, keys } => {
            let mut builder = builder;
            for key in keys {
                let public_key =
                    script_builder
                        .keys
                        .get(key)
                        .ok_or(ScriptBuilderError::KeyNotFound {
                            position: ast.position,
                            key,
                        })?;
                builder = builder.push_key(public_key);
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
                let builder = build_fragment(script_builder, ctx, ctx.get_node(*x), builder)?;
                let builder = builder.push_opcode(opcodes::all::OP_FROMALTSTACK);
                Ok(builder)
            }
            crate::parser::IdentityType::S => {
                let builder = builder.push_opcode(opcodes::all::OP_SWAP);
                let builder = build_fragment(script_builder, ctx, ctx.get_node(*x), builder)?;
                Ok(builder)
            }
            crate::parser::IdentityType::C => {
                let builder = build_fragment(script_builder, ctx, ctx.get_node(*x), builder)?;
                let builder = builder.push_opcode(opcodes::all::OP_CHECKSIG);
                Ok(builder)
            }
            crate::parser::IdentityType::D => {
                let builder = builder.push_opcode(opcodes::all::OP_DUP);
                let builder = builder.push_opcode(opcodes::all::OP_IF);
                let builder = build_fragment(script_builder, ctx, ctx.get_node(*x), builder)?;
                let builder = builder.push_opcode(opcodes::all::OP_ENDIF);
                Ok(builder)
            }
            crate::parser::IdentityType::V => {
                let builder = build_fragment(script_builder, ctx, ctx.get_node(*x), builder)?;
                let builder = builder.push_opcode(opcodes::all::OP_VERIFY);
                Ok(builder)
            }
            crate::parser::IdentityType::J => {
                let builder = builder.push_opcode(opcodes::all::OP_SIZE);
                let builder = builder.push_int(0);
                let builder = builder.push_opcode(opcodes::all::OP_0NOTEQUAL);
                let builder = builder.push_opcode(opcodes::all::OP_IF);
                let builder = build_fragment(script_builder, ctx, ctx.get_node(*x), builder)?;
                let builder = builder.push_opcode(opcodes::all::OP_ENDIF);
                Ok(builder)
            }
            crate::parser::IdentityType::N => {
                let builder = build_fragment(script_builder, ctx, ctx.get_node(*x), builder)?;
                let builder = builder.push_int(0);
                let builder = builder.push_opcode(opcodes::all::OP_0NOTEQUAL);
                Ok(builder)
            }
        },
    }
}
