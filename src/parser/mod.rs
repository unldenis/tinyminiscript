pub mod keys;

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use bitcoin::psbt::raw::Key;
use bitcoin::secp256k1;
use core::str::FromStr;

use crate::checksum;
use crate::parser::keys::KeyToken;
use crate::{
    Vec,
    descriptor::Descriptor,
    satisfy::{self, Satisfactions, Satisfier, SatisfyError},
};
use keys::PublicKeyTrait;

use bitcoin::{PubkeyHash, bip32, hashes::Hash, script::Builder};

// AST Visitor

pub trait ASTVisitor<'a, T> {
    type Error;

    fn visit_ast(&mut self, ctx: &ParserContext<'a>, node: &AST<'a>) -> Result<T, Self::Error>;

    #[inline]
    fn visit_ast_by_index(
        &mut self,
        ctx: &ParserContext<'a>,
        index: NodeIndex,
    ) -> Result<T, Self::Error> {
        self.visit_ast(ctx, &ctx.nodes[index as usize])
    }

    #[inline]
    fn visit(&mut self, ctx: &ParserContext<'a>) -> Result<T, Self::Error> {
        self.visit_ast(ctx, &ctx.get_root())
    }
}

// Position
pub type Position = usize;

// AST

#[cfg_attr(feature = "debug", derive(Debug))]
#[derive(Clone)]
pub struct AST<'a> {
    pub position: Position,
    pub fragment: Fragment<'a>,
}

pub type NodeIndex = u16;

#[cfg_attr(feature = "debug", derive(Debug))]
#[derive(Clone)]
pub enum Fragment<'a> {
    // Basic Fragments
    /// 0
    False,
    /// 1
    True,

    // Key Fragments
    /// pk_k(key)
    PkK {
        key: KeyToken,
    },
    /// pk_h(key)
    PkH {
        key: KeyToken,
    },

    // Time fragments
    /// older(n)
    Older {
        n: u32,
    },
    /// after(n)
    After {
        n: u32,
    },

    // Hash Fragments
    /// sha256(h)
    Sha256 {
        h: &'a [u8; 32],
    },
    /// hash256(h)
    Hash256 {
        h: &'a [u8; 32],
    },
    /// ripemd160(h)
    Ripemd160 {
        h: &'a [u8; 20],
    },
    /// hash160(h)
    Hash160 {
        h: &'a [u8; 20],
    },

    // Logical Fragments
    /// andor(X,Y,Z)
    AndOr {
        x: NodeIndex,
        y: NodeIndex,
        z: NodeIndex,
    },
    /// and_v(X,Y)
    AndV {
        x: NodeIndex,
        y: NodeIndex,
    },
    /// and_b(X,Y)
    AndB {
        x: NodeIndex,
        y: NodeIndex,
    },

    // /// and_n(X,Y) = andor(X,Y,0)
    // AndN { x: Box<AST>, y: Box<AST> },
    /// or_b(X,Z)
    OrB {
        x: NodeIndex,
        z: NodeIndex,
    },
    /// or_c(X,Z)
    OrC {
        x: NodeIndex,
        z: NodeIndex,
    },
    /// or_d(X,Z)
    OrD {
        x: NodeIndex,
        z: NodeIndex,
    },
    /// or_i(X,Z)
    OrI {
        x: NodeIndex,
        z: NodeIndex,
    },

    // Threshold Fragments
    /// thresh(k,X1,...,Xn)
    Thresh {
        k: i32,
        xs: Vec<NodeIndex>,
    },
    ///  multi(k,key1,...,keyn)
    /// (P2WSH only)
    Multi {
        k: i32,
        keys: Vec<KeyToken>,
    },
    /// multi_a(k,key1,...,keyn)
    /// (Tapscript only)
    MultiA {
        k: i32,
        keys: Vec<KeyToken>,
    },

    Identity {
        identity_type: IdentityType,
        x: NodeIndex,
    },

    // Descriptor Fragments
    Descriptor {
        descriptor: Descriptor,
        inner: NodeIndex,
    },

    RawPkH {
        key: KeyToken,
    },
}

#[derive(PartialEq, Clone)]
pub enum IdentityType {
    A,
    S,
    C,
    D,
    V,
    J,
    N,
}

#[cfg(feature = "debug")]
impl core::fmt::Debug for IdentityType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IdentityType::A => write!(f, "a"),
            IdentityType::S => write!(f, "s"),
            IdentityType::C => write!(f, "c"),
            IdentityType::D => write!(f, "d"),
            IdentityType::V => write!(f, "v"),
            IdentityType::J => write!(f, "j"),
            IdentityType::N => write!(f, "n"),
        }
    }
}

// Optimized tokenization using string slices instead of owned strings
#[inline]
fn split_string_with_columns<'a, F>(s: &'a str, is_separator: F) -> Vec<(&'a str, usize)>
where
    F: Fn(char) -> bool,
{
    // Pre-allocate with estimated capacity to reduce reallocations
    // let estimated_tokens = s.len() / 3 + 1; // Rough estimate
    let mut result = Vec::new();
    let mut char_indices = s.char_indices().peekable();
    let mut start = 0;
    let mut column = 1;

    while let Some((i, c)) = char_indices.peek().copied() {
        if is_separator(c) {
            if start < i {
                // Push the slice before the separator
                let part = &s[start..i];
                result.push((part, column));
                column += part.chars().count();
            }

            // Push the separator itself
            result.push((&s[i..i + c.len_utf8()], column));
            column += 1;
            char_indices.next();
            start = i + c.len_utf8();
        } else {
            char_indices.next();
        }
    }

    if start < s.len() {
        let part = &s[start..];
        result.push((part, column));
    }

    result
}

#[cfg_attr(feature = "debug", derive(Debug))]
pub enum ParseError<'a> {
    UnexpectedEof {
        context: &'static str,
    },
    UnexpectedToken {
        expected: &'static str,
        found: (&'a str, Position),
    },
    InvalidKey {
        key: &'a str,
        position: Position,
        inner: &'static str,
    },
    InvalidXOnlyKey {
        key: &'a str,
        position: Position,
    },
    UnexpectedTrailingToken {
        found: (&'a str, Position),
    },
    UnknownWrapper {
        found: char,
        position: Position,
    },
    MultiColon {
        position: Position,
    },
    InvalidChecksum,
    InvalidAbsoluteLocktime {
        locktime: u32,
        position: Position,
    },
    NonAscii,
}

#[derive(Clone)]
pub struct ParserContext<'a> {
    tokens: Vec<(&'a str, usize)>,
    current_token: usize,
    nodes: Vec<AST<'a>>,

    root: Option<AST<'a>>,

    pub(crate) top_level_descriptor: Option<Descriptor>,
    inner_descriptor: Descriptor,
}

impl<'a> ParserContext<'a> {
    #[inline]
    fn new(input: &'a str) -> Self {
        let tokens =
            split_string_with_columns(input, |c| c == '(' || c == ')' || c == ',' || c == ':');
        Self {
            tokens,
            current_token: 0,
            nodes: Vec::new(),
            root: None,
            top_level_descriptor: None,
            inner_descriptor: Descriptor::default(),
        }
    }

    // return the next token
    #[inline]
    fn next_token(&mut self) -> Option<(&'a str, usize)> {
        if self.current_token < self.tokens.len() {
            let token = self.tokens[self.current_token];
            self.current_token += 1;
            Some(token)
        } else {
            None
        }
    }

    #[inline]
    fn peek_token(&self) -> Option<(&'a str, usize)> {
        if self.current_token < self.tokens.len() {
            Some(self.tokens[self.current_token])
        } else {
            None
        }
    }

    #[inline]
    fn expect_token(&mut self, expected: &'static str) -> Result<(&'a str, usize), ParseError<'a>> {
        let (token, column) = self.next_token().ok_or(ParseError::UnexpectedEof {
            context: "expect_token",
        })?;
        if token != expected {
            return Err(ParseError::UnexpectedToken {
                expected,
                found: (token, column),
            });
        }
        Ok((token, column))
    }

    #[inline]
    fn peek_next_token(&self) -> Option<(&'a str, usize)> {
        if self.current_token + 1 < self.tokens.len() {
            Some(self.tokens[self.current_token + 1])
        } else {
            None
        }
    }

    #[inline]
    fn check_next_tokens(&self, tokens: &[&'a str]) -> bool {
        if self.current_token + tokens.len() > self.tokens.len() {
            return false;
        }

        for (i, token) in tokens.iter().enumerate() {
            if self.tokens[self.current_token + i].0 != *token {
                return false;
            }
        }
        true
    }

    #[inline]
    fn add_node(&mut self, ast: AST<'a>) -> NodeIndex {
        let index = self.nodes.len() as NodeIndex;
        self.nodes.push(ast);
        index
    }

    #[inline]
    pub fn get_node(&self, index: NodeIndex) -> &AST<'a> {
        &self.nodes[index as usize]
    }

    #[inline]
    pub fn get_root(&self) -> &AST<'a> {
        self.root.as_ref().expect("Root node not found")
    }

    #[inline]
    #[cfg(feature = "satisfy")]
    pub fn satisfy(&self, satisfier: &dyn Satisfier) -> Result<Satisfactions, SatisfyError> {
        satisfy::satisfy(self, satisfier, &self.get_root())
    }

    #[cfg(feature = "ast-printer")]
    /// Returns a tree representation of the AST.
    pub fn print_ast(&self) -> alloc::string::String {
        use crate::ast_printer;

        let mut ast_printer = ast_printer::ASTPrinter::new();
        ast_printer.print_ast(self)
    }

    #[inline]
    pub fn descriptor(&self) -> Descriptor {
        self.inner_descriptor.clone()
    }

    #[inline]
    pub fn is_wrapped(&self) -> bool {
        self.top_level_descriptor == Some(Descriptor::Sh)
    }

    /// Iterate over all the keys.
    /// Not using a Visitor pattern because it's not needed for the current use case.
    pub fn iterate_keys_mut(&mut self, mut callback: impl FnMut(&mut KeyToken)) {
        self.nodes
            .iter_mut()
            .for_each(|node| match &mut node.fragment {
                Fragment::PkK { key } => callback(key),
                Fragment::PkH { key } => callback(key),
                Fragment::RawPkH { key } => callback(key),
                Fragment::Multi { keys, .. } => {
                    for key in keys.iter_mut() {
                        callback(key);
                    }
                }
                Fragment::MultiA { keys, .. } => {
                    for key in keys.iter_mut() {
                        callback(key);
                    }
                }
                _ => (),
            });
    }

    pub fn iterate_keys(&self, mut callback: impl FnMut(&KeyToken)) {
        self.nodes
            .iter()
            .for_each(|node| match &node.fragment {
                Fragment::PkK { key } => callback(key),
                Fragment::PkH { key } => callback(key),
                Fragment::RawPkH { key } => callback(key),
                Fragment::Multi { keys, .. } => {
                    for key in keys.iter() {
                        callback(key);
                    }
                }
                Fragment::MultiA { keys, .. } => {
                    for key in keys.iter() {
                        callback(key);
                    }
                }   
                _ => (),
            });
    }

    /// Derive all the keys in the AST.
    pub fn derive(&mut self, index: u32) -> Result<(), String> {
        for node in &mut self.nodes {
            match &mut node.fragment {
                Fragment::PkK { key } | Fragment::PkH { key } | Fragment::RawPkH { key } => {
                    let derived = key.derive(index)?;
                    key.inner = derived;
                }
                Fragment::Multi { keys, k } => {
                    for key in keys.iter_mut() {
                        let derived = key.derive(index)?;
                        key.inner = derived;
                    }
                }
                Fragment::MultiA { keys, k } => {
                    for key in keys.iter_mut() {
                        let derived = key.derive(index)?;
                        key.inner = derived;
                    }
                }
                _ => (),
            }
        }
        Ok(())
    }

    /// Serialize the AST to a string.
    #[inline]
    pub fn serialize(&self) -> String {
        let mut serializer = crate::serialize::Serializer::new();
        serializer.serialize(self)
    }
}

#[inline]
pub fn parse<'a>(input: &'a str) -> Result<ParserContext<'a>, ParseError<'a>> {

    // check if the input is ascii
    if !input.is_ascii() {
        return Err(ParseError::NonAscii);
    }

    let mut ctx = ParserContext::new(input);

    let root = parse_descriptor(&mut ctx)?;
    ctx.root = Some(root);


    // should be no more tokens
    let next_token = ctx.peek_token();
    if next_token.is_some() {
        let next_token = next_token.unwrap();
        if next_token.0.starts_with("#") {
            if checksum::verify_checksum(next_token.0).is_err() {
                return Err(ParseError::InvalidChecksum);
            }
        } else {
            return Err(ParseError::UnexpectedTrailingToken { found: next_token });
        }
    }


    Ok(ctx)
}

fn parse_descriptor<'a>(ctx: &mut ParserContext<'a>) -> Result<AST<'a>, ParseError<'a>> {
    let (token, column) = ctx.peek_token().ok_or(ParseError::UnexpectedEof {
        context: "parse_descriptor",
    })?;

    let descriptor = Descriptor::try_from(token).map_err(|_| ParseError::UnexpectedToken {
        expected: "descriptor",
        found: (token, column),
    })?;

    if ctx.top_level_descriptor.is_none() {
        ctx.top_level_descriptor = Some(descriptor.clone());
    }
    ctx.inner_descriptor = descriptor.clone();

    // If the descriptor is bare, we need to parse the inner descriptor
    if descriptor == Descriptor::Bare {
        let inner = parse_internal(ctx, true)?;
        return Ok(AST {
            position: column,
            fragment: Fragment::Descriptor {
                descriptor: Descriptor::Bare,
                inner: ctx.add_node(inner),
            },
        });
    } else {
        ctx.next_token();
    }

    // For sh descriptors, we need to check what's inside
    if descriptor == Descriptor::Sh
        && (ctx.check_next_tokens(&["(", "wsh"]) || ctx.check_next_tokens(&["(", "wpkh"]))
    {
        return parse_sh_descriptor(ctx, (token, column));
    }

    // Standard descriptor parsing
    let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
    let inner = parse_internal(ctx, true)?;
    let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

    Ok(AST {
        position: column,
        fragment: Fragment::Descriptor {
            descriptor,
            inner: ctx.add_node(inner),
        },
    })
}

fn parse_sh_descriptor<'a>(
    ctx: &mut ParserContext<'a>,
    sh: (&'a str, usize),
) -> Result<AST<'a>, ParseError<'a>> {
    let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;

    // Parse the inner descriptor directly
    let inner = parse_descriptor(ctx)?;

    let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

    Ok(AST {
        position: sh.1,
        fragment: Fragment::Descriptor {
            descriptor: Descriptor::Sh,
            inner: ctx.add_node(inner),
        },
    })
}

fn is_invalid_number(n: &str) -> bool {
    n.is_empty() || !n.chars().next().unwrap().is_ascii_digit() || n.starts_with('0')
}   

fn parse_internal<'a>(
    ctx: &mut ParserContext<'a>,
    first_fragment: bool,
) -> Result<AST<'a>, ParseError<'a>> {

    let (token, column) = ctx
        .peek_token()
        .ok_or(ParseError::UnexpectedEof { context: "parse" })?;

    match ctx.descriptor() {
        Descriptor::Pkh | Descriptor::Wpkh => {
            ctx.next_token(); // Advance past the key

            let key = keys::parse_key((token, column), &ctx.inner_descriptor)?;

            Ok(AST {
                position: column,
                fragment: Fragment::RawPkH { key },
            })
        }
        _ => {
            match token {
                "pk_k" => {
                    ctx.next_token(); // Advance past "pk_k"
                    let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
                    let key_token = ctx
                        .next_token()
                        .ok_or(ParseError::UnexpectedEof { context: "pk_k" })?;

                    let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

                    // Get the key type based on the inner descriptor
                    let key = keys::parse_key(key_token, &ctx.inner_descriptor)?;

                    Ok(AST {
                        position: column,
                        fragment: Fragment::PkK { key },
                    })
                }
                "pk_h" => {
                    ctx.next_token(); // Advance past "pk_h"
                    let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
                    let key_token = ctx
                        .next_token()
                        .ok_or(ParseError::UnexpectedEof { context: "pk_h" })?;

                    let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

                    // Get the key type based on the inner descriptor
                    let key = keys::parse_key(key_token, &ctx.inner_descriptor)?;

                    Ok(AST {
                        position: column,
                        fragment: Fragment::PkH { key },
                    })
                }
                "pk" => {
                    // pk(key) = c:pk_k(key)

                    ctx.next_token(); // Advance past "pk"
                    let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
                    let (key, key_column) = ctx
                        .next_token()
                        .ok_or(ParseError::UnexpectedEof { context: "pk" })?;

                    let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

                    // Get the key type based on the inner descriptor
                    let key = keys::parse_key((key, key_column), &ctx.inner_descriptor)?;

                    let mut ast = AST {
                        position: column,
                        fragment: Fragment::PkK { key },
                    };

                    // wrap in c: identity
                    ast = AST {
                        position: column,
                        fragment: Fragment::Identity {
                            identity_type: IdentityType::C,
                            x: ctx.add_node(ast),
                        },
                    };
                    Ok(ast)
                }
                "pkh" => {
                    // pkh(key) = c:pk_h(key)

                    ctx.next_token(); // Advance past "pkh"
                    let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
                    let key_token = ctx
                        .next_token()
                        .ok_or(ParseError::UnexpectedEof { context: "pkh" })?;

                    let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

                    // Get the key type based on the inner descriptor
                    let key = keys::parse_key(key_token, &ctx.inner_descriptor)?;

                    let mut ast = AST {
                        position: column,
                        fragment: Fragment::PkH { key },
                    };

                    // wrap in c: identity
                    ast = AST {
                        position: column,
                        fragment: Fragment::Identity {
                            identity_type: IdentityType::C,
                            x: ctx.add_node(ast),
                        },
                    };
                    Ok(ast)
                }

                "older" => {
                    ctx.next_token(); // Advance past "older"
                    let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
                    let (n, n_column) = ctx
                        .next_token()
                        .ok_or(ParseError::UnexpectedEof { context: "older" })?;
                    let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

                    // Check if the number starts with a digit 1-9
                    if is_invalid_number(&n) {
                        return Err(ParseError::UnexpectedToken {
                            expected: "Number must start with a digit 1-9",
                            found: (n, n_column),
                        });
                    }

                    // check if n is u32
                    let n = n.parse::<u32>().map_err(|_| ParseError::UnexpectedToken {
                        expected: "u32",
                        found: (n, n_column),
                    })?;

                    // check if the locktime is within the allowed range
                    if let Err(locktime) = crate::limits::check_absolute_locktime(n) {
                        return Err(ParseError::InvalidAbsoluteLocktime { locktime, position: n_column });
                    }

                    Ok(AST {
                        position: column,
                        fragment: Fragment::Older { n },
                    })
                }

                "after" => {
                    ctx.next_token(); // Advance past "after"
                    let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
                    let (n, n_column) = ctx
                        .next_token()
                        .ok_or(ParseError::UnexpectedEof { context: "after" })?;
                    let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

                    // check if n is u32

                    // Check if the number starts with a digit 1-9
                    if is_invalid_number(&n) {
                        return Err(ParseError::UnexpectedToken {
                            expected: "Number must start with a digit 1-9",
                            found: (n, n_column),
                        });
                    }

                    let n = n.parse::<u32>().map_err(|_| ParseError::UnexpectedToken {
                        expected: "u32",
                        found: (n, n_column),
                    })?;

                    // check if the locktime is within the allowed range
                    if let Err(locktime) = crate::limits::check_absolute_locktime(n) {
                        return Err(ParseError::InvalidAbsoluteLocktime { locktime, position: n_column });
                    }

                    Ok(AST {
                        position: column,
                        fragment: Fragment::After { n },
                    })
                }

                "sha256" => {
                    ctx.next_token(); // Advance past "sha256"
                    let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
                    let (h, _h_column) = ctx
                        .next_token()
                        .ok_or(ParseError::UnexpectedEof { context: "sha256" })?;
                    let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

                    let h: &'a [u8; 32] =
                        h.as_bytes()
                            .try_into()
                            .map_err(|_| ParseError::UnexpectedToken {
                                expected: "[u8; 32]",
                                found: (h, _h_column),
                            })?;

                    Ok(AST {
                        position: column,
                        fragment: Fragment::Sha256 { h },
                    })
                }

                "hash256" => {
                    ctx.next_token(); // Advance past "hash256"
                    let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
                    let (h, _h_column) = ctx
                        .next_token()
                        .ok_or(ParseError::UnexpectedEof { context: "hash256" })?;
                    let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

                    let h: &'a [u8; 32] =
                        h.as_bytes()
                            .try_into()
                            .map_err(|_| ParseError::UnexpectedToken {
                                expected: "[u8; 32]",
                                found: (h, _h_column),
                            })?;

                    Ok(AST {
                        position: column,
                        fragment: Fragment::Hash256 { h },
                    })
                }

                "ripemd160" => {
                    ctx.next_token(); // Advance past "ripemd160"
                    let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
                    let (h, _h_column) = ctx.next_token().ok_or(ParseError::UnexpectedEof {
                        context: "ripemd160",
                    })?;
                    let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

                    let h: &'a [u8; 20] =
                        h.as_bytes()
                            .try_into()
                            .map_err(|_| ParseError::UnexpectedToken {
                                expected: "[u8; 20]",
                                found: (h, _h_column),
                            })?;

                    Ok(AST {
                        position: column,
                        fragment: Fragment::Ripemd160 { h },
                    })
                }

                "hash160" => {
                    ctx.next_token(); // Advance past "hash160"
                    let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
                    let (h, _h_column) = ctx
                        .next_token()
                        .ok_or(ParseError::UnexpectedEof { context: "hash160" })?;
                    let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

                    let h: &'a [u8; 20] =
                        h.as_bytes()
                            .try_into()
                            .map_err(|_| ParseError::UnexpectedToken {
                                expected: "[u8; 20]",
                                found: (h, _h_column),
                            })?;

                    Ok(AST {
                        position: column,
                        fragment: Fragment::Hash160 { h },
                    })
                }

                "andor" => {
                    ctx.next_token(); // Advance past "andor"

                    let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;

                    let x = parse_internal(ctx, false)?;

                    let (_comma, _comma_column) = ctx.expect_token(",")?;

                    let y = parse_internal(ctx, false)?;

                    let (_comma, _comma_column) = ctx.expect_token(",")?;

                    let z = parse_internal(ctx, false)?;

                    let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

                    Ok(AST {
                        position: column,
                        fragment: Fragment::AndOr {
                            x: ctx.add_node(x),
                            y: ctx.add_node(y),
                            z: ctx.add_node(z),
                        },
                    })
                }

                "and_v" => {
                    ctx.next_token(); // Advance past "and_v"
                    let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
                    let x = parse_internal(ctx, false)?;
                    let (_comma, _comma_column) = ctx.expect_token(",")?;
                    let y = parse_internal(ctx, false)?;
                    let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

                    Ok(AST {
                        position: column,
                        fragment: Fragment::AndV {
                            x: ctx.add_node(x),
                            y: ctx.add_node(y),
                        },
                    })
                }

                "and_b" => {
                    ctx.next_token(); // Advance past "and_b"
                    let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
                    let x = parse_internal(ctx, false)?;
                    let (_comma, _comma_column) = ctx.expect_token(",")?;
                    let y = parse_internal(ctx, false)?;
                    let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

                    Ok(AST {
                        position: column,
                        fragment: Fragment::AndB {
                            x: ctx.add_node(x),
                            y: ctx.add_node(y),
                        },
                    })
                }

                "and_n" => {
                    // and_n(X,Y) = andor(X,Y,0)

                    ctx.next_token(); // Advance past "and_n"
                    let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
                    let x = parse_internal(ctx, false)?;
                    let (_comma, _comma_column) = ctx.expect_token(",")?;
                    let y = parse_internal(ctx, false)?;
                    let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

                    let ast = AST {
                        position: column,
                        fragment: Fragment::AndOr {
                            x: ctx.add_node(x),
                            y: ctx.add_node(y),
                            z: ctx.add_node(AST {
                                position: column,
                                fragment: Fragment::False,
                            }),
                        },
                    };
                    Ok(ast)
                }

                "or_b" => {
                    ctx.next_token(); // Advance past "or_b"
                    let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
                    let x = parse_internal(ctx, false)?;
                    let (_comma, _comma_column) = ctx.expect_token(",")?;
                    let z = parse_internal(ctx, false)?;
                    let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

                    Ok(AST {
                        position: column,
                        fragment: Fragment::OrB {
                            x: ctx.add_node(x),
                            z: ctx.add_node(z),
                        },
                    })
                }

                "or_c" => {
                    ctx.next_token(); // Advance past "or_c"
                    let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
                    let x = parse_internal(ctx, false)?;
                    let (_comma, _comma_column) = ctx.expect_token(",")?;
                    let z = parse_internal(ctx, false)?;
                    let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

                    Ok(AST {
                        position: column,
                        fragment: Fragment::OrC {
                            x: ctx.add_node(x),
                            z: ctx.add_node(z),
                        },
                    })
                }

                "or_d" => {
                    ctx.next_token(); // Advance past "or_d"
                    let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
                    let x = parse_internal(ctx, false)?;
                    let (_comma, _comma_column) = ctx.expect_token(",")?;
                    let z = parse_internal(ctx, false)?;
                    let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

                    Ok(AST {
                        position: column,
                        fragment: Fragment::OrD {
                            x: ctx.add_node(x),
                            z: ctx.add_node(z),
                        },
                    })
                }

                "or_i" => {
                    ctx.next_token(); // Advance past "or_i"
                    let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
                    let x = parse_internal(ctx, false)?;
                    let (_comma, _comma_column) = ctx.expect_token(",")?;
                    let z = parse_internal(ctx, false)?;
                    let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

                    Ok(AST {
                        position: column,
                        fragment: Fragment::OrI {
                            x: ctx.add_node(x),
                            z: ctx.add_node(z),
                        },
                    })
                }

                "thresh" => {
                    ctx.next_token(); // Advance past "thresh"
                    let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
                    let (k, k_column) = ctx
                        .next_token()
                        .ok_or(ParseError::UnexpectedEof { context: "thresh" })?;

                    // Check if the number starts with a digit 1-9
                    if is_invalid_number(&k) {
                        return Err(ParseError::UnexpectedToken {
                            expected: "Number must start with a digit 1-9",
                            found: (k, k_column),
                        });
                    }

                    let k = k.parse::<i32>().map_err(|_| ParseError::UnexpectedToken {
                        expected: "i32",
                        found: (k, k_column),
                    })?;

                    // TODO: Pre-allocate with reasonable capacity to reduce reallocations
                    let mut xs = Vec::new();
                    while let Some((token, _column)) = ctx.peek_token() {
                        if token == ")" {
                            break;
                        } else if token == "," {
                            ctx.next_token();
                        }
                        let x = parse_internal(ctx, false)?;
                        xs.push(ctx.add_node(x));
                    }

                    let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

                    Ok(AST {
                        position: column,
                        fragment: Fragment::Thresh { k, xs },
                    })
                }

                "multi" => {
                    ctx.next_token(); // Advance past "multi"
                    let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
                    let (k, k_column) = ctx
                        .next_token()
                        .ok_or(ParseError::UnexpectedEof { context: "multi" })?;
                    let k = k.parse::<i32>().map_err(|_| ParseError::UnexpectedToken {
                        expected: "i32",
                        found: (k, k_column),
                    })?;

                    // Pre-allocate with reasonable capacity
                    let mut keys = Vec::new();
                    while let Some((token, _column)) = ctx.peek_token() {
                        if token == ")" {
                            break;
                        } else if token == "," {
                            ctx.next_token();
                        }
                        let (key, key_column) = ctx
                            .next_token()
                            .ok_or(ParseError::UnexpectedEof { context: "multi" })?;

                        let key = bitcoin::PublicKey::from_str(key).map_err(|e| {
                            ParseError::InvalidKey {
                                key,
                                position: key_column,
                                inner: "Invalid bitcoin::PublicKey key",
                            }
                        })?;
                        keys.push(KeyToken {
                            inner: alloc::rc::Rc::new(key),
                        });
                    }

                    let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

                    Ok(AST {
                        position: column,
                        fragment: Fragment::Multi { k, keys },
                    })
                }

                "multi_a" => {
                    ctx.next_token(); // Advance past "multi_a"
                    let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
                    let (k, k_column) = ctx
                        .next_token()
                        .ok_or(ParseError::UnexpectedEof { context: "multi_a" })?;
                    let k = k.parse::<i32>().map_err(|_| ParseError::UnexpectedToken {
                        expected: "i32",
                        found: (k, k_column),
                    })?;

                    // Pre-allocate with reasonable capacity
                    let mut keys = Vec::new();
                    while let Some((token, _column)) = ctx.peek_token() {
                        if token == ")" {
                            break;
                        } else if token == "," {
                            ctx.next_token();
                        }
                        let (key, key_column) = ctx
                            .next_token()
                            .ok_or(ParseError::UnexpectedEof { context: "multi_a" })?;
                        let key = bitcoin::XOnlyPublicKey::from_str(key).map_err(|e| {
                            ParseError::InvalidXOnlyKey {
                                key,
                                position: key_column,
                            }
                        })?;
                        keys.push(KeyToken {
                            inner: alloc::rc::Rc::new(key),
                        });
                    }

                    let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

                    Ok(AST {
                        position: column,
                        fragment: Fragment::MultiA { k, keys },
                    })
                }

                _ => {
                    // the top fragment cant be an identity

                    if let Some((peek_token, _peek_token_column)) = ctx.peek_next_token() {
                        if peek_token == ":" {
                            ctx.next_token(); // Advance past identity type

                            ctx.expect_token(":")?;

                            // multi colon is not allowed
                            // example: sh(uuuuuuuuuuuuuu:uuuuuu:1)
                            if let Some((peek_token, peek_token_column)) = ctx.peek_next_token() {
                                if peek_token == ":" {
                                    return Err(ParseError::MultiColon {
                                        position: peek_token_column,
                                    });
                                }
                            }

                            // identity is a list of inner identities, eg av:X

                            let mut node: AST = parse_internal(ctx, first_fragment)?;

                            // fix critical: https://github.com/unldenis/tinyminiscript/issues/3
                            let identities = token.chars().rev().take(500);

                            for id_type in identities {
                                if id_type == 'a'
                                    || id_type == 'v'
                                    || id_type == 'c'
                                    || id_type == 'd'
                                    || id_type == 's'
                                    || id_type == 'j'
                                    || id_type == 'n'
                                {
                                    let identity_type = match id_type {
                                        'a' => IdentityType::A,
                                        'v' => IdentityType::V,
                                        'c' => IdentityType::C,
                                        'd' => IdentityType::D,
                                        's' => IdentityType::S,
                                        'j' => IdentityType::J,
                                        'n' => IdentityType::N,
                                        _ => continue,
                                    };

                                    node = AST {
                                        position: column,
                                        fragment: Fragment::Identity {
                                            identity_type,
                                            x: ctx.add_node(node),
                                        },
                                    }
                                } else if id_type == 't' {
                                    // t:X = and_v(X,1)
                                    node = AST {
                                        position: column,
                                        fragment: Fragment::AndV {
                                            x: ctx.add_node(node),
                                            y: ctx.add_node(AST {
                                                position: column,
                                                fragment: Fragment::True,
                                            }),
                                        },
                                    }
                                } else if id_type == 'l' {
                                    // l:X = or_i(0,X)
                                    node = AST {
                                        position: column,
                                        fragment: Fragment::OrI {
                                            x: ctx.add_node(AST {
                                                position: column,
                                                fragment: Fragment::False,
                                            }),
                                            z: ctx.add_node(node),
                                        },
                                    }
                                } else if id_type == 'u' {
                                    // u:X = or_i(X,0)
                                    node = AST {
                                        position: column,
                                        fragment: Fragment::OrI {
                                            x: ctx.add_node(node),
                                            z: ctx.add_node(AST {
                                                position: column,
                                                fragment: Fragment::False,
                                            }),
                                        },
                                    }
                                } else {
                                    // invalid identity type
                                    return Err(ParseError::UnknownWrapper {
                                        found: id_type,
                                        position: column,
                                    });
                                }
                            }

                            return Ok(node);
                        }
                    }

                    // the top fragment cant be a bool
                    if !first_fragment || ctx.inner_descriptor != Descriptor::Tr {
                        return parse_bool(ctx);
                    }

                    Err(ParseError::UnexpectedToken {
                        expected: "pk_k or pk_h or pk or pkh or older or after or sha256 or hash256 or ripemd160 or hash160 or andor or and_v or and_b or and_n or or_b or or_c or or_d or or_i or thresh or multi or multi_a or a:pk_k(key) or v:pk_k(key) or c:pk_k(key) or d:pk_k(key) or s:pk_k(key) or j:pk_k(key) or n:pk_k(key)",
                        found: (token, column),
                    })
                }
            }
        }
    }
}

fn parse_bool<'a>(ctx: &mut ParserContext<'a>) -> Result<AST<'a>, ParseError<'a>> {
    let (token, column) = ctx.peek_token().ok_or(ParseError::UnexpectedEof {
        context: "parse_bool",
    })?;

    match token {
        "0" => {
            ctx.next_token();
            Ok(AST {
                position: column,
                fragment: Fragment::False,
            })
        }
        "1" => {
            ctx.next_token();
            Ok(AST {
                position: column,
                fragment: Fragment::True,
            })
        }
        _ => {
            return Err(ParseError::UnexpectedToken {
                expected: "0 or 1",
                found: (token, column),
            });
        }
    }
}
