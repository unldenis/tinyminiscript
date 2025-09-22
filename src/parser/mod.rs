pub mod keys;

use core::str::FromStr;
use alloc::string::String;

use bitcoin::{Address, Network, ScriptBuf};

use crate::parser::keys::{KeyToken, KeyTokenInner};
use crate::script::ScriptBuilderError;
use crate::utils::checksum;
use crate::{Vec, descriptor::Descriptor};

// AST Visitor

pub(crate) trait ASTVisitor<T> {
    type Error;

    fn visit_ast(&mut self, ctx: &ParserContext, node: &AST) -> Result<T, Self::Error>;

    #[inline]
    fn visit_ast_by_index(
        &mut self,
        ctx: &ParserContext,
        index: NodeIndex,
    ) -> Result<T, Self::Error> {
        self.visit_ast(ctx, &ctx.nodes[index as usize])
    }

    #[inline]
    fn visit(&mut self, ctx: &ParserContext) -> Result<T, Self::Error> {
        self.visit_ast(ctx, &ctx.get_root())
    }
}

// Position
pub type Position = u16;

// AST

#[cfg_attr(feature = "debug", derive(Debug))]
#[derive(Clone)]
pub struct AST {
    pub position: Position,
    pub fragment: Fragment,
}

pub type NodeIndex = u16;

#[cfg_attr(feature = "debug", derive(Debug))]
#[derive(Clone)]
pub enum Fragment {
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
        h: [u8; 32],
    },
    /// hash256(h)
    Hash256 {
        h: [u8; 32],
    },
    /// ripemd160(h)
    Ripemd160 {
        h: [u8; 20],
    },
    /// hash160(h)
    Hash160 {
        h: [u8; 20],
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

    RawTr {
        key: KeyToken,
        inner: Option<NodeIndex>,
    }
}

#[derive(PartialEq, Clone)]
#[repr(u8)]
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
fn split_string_with_columns<'a, F>(s: &'a str, is_separator: F) -> Vec<(&'a str, Position)>
where
    F: Fn(char) -> bool,
{
    // Pre-allocate with estimated capacity to reduce reallocations
    let estimated_tokens = s.len() / 3 + 1; // Rough estimate
    let mut result: Vec<(&'a str, Position)> = Vec::with_capacity(estimated_tokens);
    let mut char_indices = s.char_indices().peekable();
    let mut start = 0;
    let mut column = 1;

    while let Some((i, c)) = char_indices.peek().copied() {
        if is_separator(c) {
            if start < i {
                // Push the slice before the separator
                let part = &s[start..i];
                result.push((part, column));
                column += part.chars().count() as u16;
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
    InvalidHex {
        position: Position,
    },
    InvalidHexLength {
        expected: usize,
        found: usize,
        position: Position,
    },
}

#[derive(Clone)]
pub struct ParserContext<'a> {
    tokens: Vec<(&'a str, Position)>,
    current_token: usize,
    pub(crate) nodes: Vec<AST>,

    root: Option<AST>,

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
    fn next_token(&mut self, context: &'static str) -> Result<(&'a str, Position), ParseError<'a>> {
        if self.current_token < self.tokens.len() {
            let token = self.tokens[self.current_token];
            self.current_token += 1;
            Ok(token)
        } else {
            Err(ParseError::UnexpectedEof {
                context,
            })
        }
    }

    fn peek_token(&self) -> Option<(&'a str, Position)> {
        if self.current_token < self.tokens.len() {
            Some(self.tokens[self.current_token])
        } else {
            None
        }
    }

    fn expect_token(
        &mut self,
        context: &'static str,
        expected: &'static str,
    ) -> Result<(&'a str, Position), ParseError<'a>> {
        let (token, column) = self.next_token(context)?;
        if token != expected {
            return Err(ParseError::UnexpectedToken {
                expected,
                found: (token, column),
            });
        }
        Ok((token, column))
    }

    fn peek_next_token(&self) -> Option<(&'a str, Position)> {
        if self.current_token + 1 < self.tokens.len() {
            Some(self.tokens[self.current_token + 1])
        } else {
            None
        }
    }

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

    fn add_node(&mut self, ast: AST) -> NodeIndex {
        let index = self.nodes.len() as NodeIndex;
        self.nodes.push(ast);
        index
    }

    fn parse_inner_paren(&mut self, context: &'static str) -> Result<(&'a str, Position), ParseError<'a>> {
        self.next_token(context)?; // Advance past the fragment name

        let (_l_paren, _l_paren_column) = self.expect_token(context, "(")?;
        let inner = self.next_token(context)?;
        let (_r_paren, _r_paren_column) = self.expect_token(context, ")")?;
        Ok(inner)
    }

    fn parse_call<const N: usize>(&mut self, context: &'static str) -> Result<[AST; N], ParseError<'a>> {
        self.next_token(context)?; // Advance past the fragment name

        let (_l_paren, _l_paren_column) = self.expect_token(context, "(")?;
        
        // Create uninitialized array
        let mut asts: [AST; N] = unsafe {core::mem::zeroed()};
        
        // Fill first element
        asts[0] = parse_internal(self)?;
        
        // Fill remaining elements
        for i in 1..N {
            let (_comma, _comma_column) = self.expect_token(context, ",")?;
            asts[i] = parse_internal(self)?;
        }

        let (_r_paren, _r_paren_column) = self.expect_token(context, ")")?;

        // Convert to initialized array
        Ok(asts)
    }

    pub fn get_node(&self, index: NodeIndex) -> &AST {
        &self.nodes[index as usize]
    }

    pub fn get_root(&self) -> &AST {
        self.root.as_ref().expect("Root node not found")
    }

    #[cfg(feature = "satisfy")]
    pub fn satisfy(&self, satisfier: &dyn crate::satisfy::Satisfier) -> Result<crate::satisfy::Satisfactions, crate::satisfy::SatisfyError> {
        crate::satisfy::satisfy(self, satisfier, &self.get_root())
    }

    pub fn descriptor(&self) -> Descriptor {
        self.inner_descriptor.clone()
    }

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
        self.nodes.iter().for_each(|node| match &node.fragment {
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
                    *key = derived;
                }
                Fragment::Multi { keys, k } => {
                    for key in keys.iter_mut() {
                        let derived = key.derive(index)?;
                        *key = derived;
                    }
                }
                Fragment::MultiA { keys, k } => {
                    for key in keys.iter_mut() {
                        let derived = key.derive(index)?;
                        *key = derived;
                    }
                }
                _ => (),
            }
        }
        Ok(())
    }

    /// Serialize the AST to a string.
    pub fn serialize(&self) -> String {
        let mut serializer = crate::utils::serialize::Serializer::new();
        serializer.serialize(self)
    }

    pub fn build_script(&self) -> Result<ScriptBuf, ScriptBuilderError<'a>> {
        crate::script::build_script(self)
    }

    pub fn build_address(&self, network: Network) -> Result<Address, ScriptBuilderError<'a>> {
        crate::script::build_address(self, network)
    }
}

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
            if checksum::verify_checksum(input).is_err() {
                return Err(ParseError::InvalidChecksum);
            }
        } else {
            return Err(ParseError::UnexpectedTrailingToken { found: next_token });
        }
    }

    Ok(ctx)
}

fn parse_descriptor<'a>(ctx: &mut ParserContext<'a>) -> Result<AST, ParseError<'a>> {
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
        let inner = parse_internal(ctx)?;
        return Ok(AST {
            position: column,
            fragment: Fragment::Descriptor {
                descriptor: Descriptor::Bare,
                inner: ctx.add_node(inner),
            },
        });
    } else {
        ctx.next_token("parse_descriptor")?;
    }

    // For sh descriptors, we need to check what's inside
    if descriptor == Descriptor::Sh
        && (ctx.check_next_tokens(&["(", "wsh"]) || ctx.check_next_tokens(&["(", "wpkh"]))
    {
        return parse_sh_descriptor(ctx, (token, column));
    }

    // Standard descriptor parsing
    let (_l_paren, _l_paren_column) = ctx.expect_token("parse_descriptor", "(")?;
    let inner = parse_top_internal(ctx)?;
    let (_r_paren, _r_paren_column) = ctx.expect_token("parse_descriptor", ")")?;

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
    sh: (&'a str, Position),
) -> Result<AST, ParseError<'a>> {
    let (_l_paren, _l_paren_column) = ctx.expect_token("parse_sh_descriptor", "(")?;

    // Parse the inner descriptor directly
    let inner = parse_descriptor(ctx)?;

    let (_r_paren, _r_paren_column) = ctx.expect_token("parse_sh_descriptor", ")")?;

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

fn parse_hex_to_bytes<'a, const N: usize>(
    h: &'a str,
    position: Position,
) -> Result<[u8; N], ParseError<'a>> {
    use bitcoin::hex::FromHex;
    let bytes = <[u8; N]>::from_hex(h).map_err(|_| ParseError::UnexpectedToken {
        expected: "hex string",
        found: (h, position),
    })?;

    Ok(bytes)
}

fn parse_top_internal<'a>(
    ctx: &mut ParserContext<'a>,
) -> Result<AST, ParseError<'a>> {
    let (token, column) = ctx
        .peek_token()
        .ok_or(ParseError::UnexpectedEof { context: "parse_top_internal" })?;
    match ctx.descriptor() {
        Descriptor::Pkh | Descriptor::Wpkh => {
            ctx.next_token("parse_top_internal")?; // Advance past the key

            let key = keys::parse_key((token, column), &ctx.inner_descriptor)?;

            Ok(AST {
                position: column,
                fragment: Fragment::RawPkH { key },
            })
        }
        Descriptor::Tr => {
            ctx.next_token("parse_top_internal")?; // Advance past the key

            let key = keys::parse_key((token, column), &ctx.inner_descriptor)?;


            if let Some((next_token, next_column)) = ctx.peek_token() {
                if next_token == "," {

                    ctx.next_token("parse_top_internal")?; // Advance past the comma
                    let inner = parse_internal(ctx)?;
                    return Ok(AST {
                        position: column,
                        fragment: Fragment::RawTr { key, inner: Some(ctx.add_node(inner)) },
                    });
                }

            }
            Ok(AST {
                position: column,
                fragment: Fragment::RawTr { key, inner: None },
            })
        }
        _ => {
            return parse_internal(ctx);
        }
    }

}
fn parse_internal<'a>(
    ctx: &mut ParserContext<'a>,
) -> Result<AST, ParseError<'a>> {
    let (token, column) = ctx
        .peek_token()
        .ok_or(ParseError::UnexpectedEof { context: "parse" })?;

    match token {
        "pk_k" => {
            let key_token = ctx.parse_inner_paren("pk_k")?;

            // Get the key type based on the inner descriptor
            let key = keys::parse_key(key_token, &ctx.inner_descriptor)?;

            Ok(AST {
                position: column,
                fragment: Fragment::PkK { key },
            })
        }
        "pk_h" => {
            let key_token = ctx.parse_inner_paren("pk_h")?;

            // Get the key type based on the inner descriptor
            let key = keys::parse_key(key_token, &ctx.inner_descriptor)?;

            Ok(AST {
                position: column,
                fragment: Fragment::PkH { key },
            })
        }
        "pk" => {
            // pk(key) = c:pk_k(key)    
            let (key, key_column) = ctx.parse_inner_paren("pk")?;

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
            let key_token = ctx.parse_inner_paren("pkh")?;

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
            let (n, n_column) = ctx.parse_inner_paren("older")?;

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
                return Err(ParseError::InvalidAbsoluteLocktime {
                    locktime,
                    position: n_column,
                });
            }

            Ok(AST {
                position: column,
                fragment: Fragment::Older { n },
            })
        }

        "after" => {
            let (n, n_column) = ctx.parse_inner_paren("after")?;

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
                return Err(ParseError::InvalidAbsoluteLocktime {
                    locktime,
                    position: n_column,
                });
            }

            Ok(AST {
                position: column,
                fragment: Fragment::After { n },
            })
        }

        "sha256" => {
            let (h, _h_column) = ctx.parse_inner_paren("sha256")?;

            let h: [u8; 32] = parse_hex_to_bytes(h, _h_column)?;

            Ok(AST {
                position: column,
                fragment: Fragment::Sha256 { h },
            })
        }

        "hash256" => {
            let (h, _h_column) = ctx.parse_inner_paren("hash256")?;

            let h: [u8; 32] = parse_hex_to_bytes(h, _h_column)?;

            Ok(AST {
                position: column,
                fragment: Fragment::Hash256 { h },
            })
        }

        "ripemd160" => {
            let (h, _h_column) = ctx.parse_inner_paren("ripemd160")?;

            let h: [u8; 20] = parse_hex_to_bytes(h, _h_column)?;

            Ok(AST {
                position: column,
                fragment: Fragment::Ripemd160 { h },
            })
        }

        "hash160" => {
            let (h, _h_column) = ctx.parse_inner_paren("hash160")?;

            let h: [u8; 20] = parse_hex_to_bytes(h, _h_column)?;

            Ok(AST {
                position: column,
                fragment: Fragment::Hash160 { h },
            })
        }

        "andor" => {
            let [x, y, z] = ctx.parse_call("andor")?;

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
            let [x, y] = ctx.parse_call("and_v")?;

            Ok(AST {
                position: column,
                fragment: Fragment::AndV {
                    x: ctx.add_node(x),
                    y: ctx.add_node(y),
                },
            })
        }

        "and_b" => {
            let [x, y] = ctx.parse_call("and_b")?;

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

            let [x, y] = ctx.parse_call("and_n")?;

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
            let [x, z] = ctx.parse_call("or_b")?;

            Ok(AST {
                position: column,
                fragment: Fragment::OrB {
                    x: ctx.add_node(x),
                    z: ctx.add_node(z),
                },
            })
        }

        "or_c" => {
            let [x, z] = ctx.parse_call("or_c")?;

            Ok(AST {
                position: column,
                fragment: Fragment::OrC {
                    x: ctx.add_node(x),
                    z: ctx.add_node(z),
                },
            })
        }

        "or_d" => {
            let [x, z] = ctx.parse_call("or_d")?;

            Ok(AST {
                position: column,
                fragment: Fragment::OrD {
                    x: ctx.add_node(x),
                    z: ctx.add_node(z),
                },
            })
        }

        "or_i" => {
            let [x, z] = ctx.parse_call("or_i")?;

            Ok(AST {
                position: column,
                fragment: Fragment::OrI {
                    x: ctx.add_node(x),
                    z: ctx.add_node(z),
                },
            })
        }

        "thresh" => {
            ctx.next_token("thresh")?; // Advance past "thresh"
            let (_l_paren, _l_paren_column) = ctx.expect_token("thresh", "(")?;
            let (k, k_column) = ctx
                .next_token("thresh")?;

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

            let estimated_tokens = k as usize;
            let mut xs = Vec::with_capacity(estimated_tokens);

            while let Some((token, _column)) = ctx.peek_token() {
                if token == ")" {
                    break;
                }
                ctx.expect_token("thresh", ",")?;

                let x = parse_internal(ctx)?;
                xs.push(ctx.add_node(x));
            }

            let (_r_paren, _r_paren_column) = ctx.expect_token("thresh", ")")?;

            Ok(AST {
                position: column,
                fragment: Fragment::Thresh { k, xs },
            })
        }

        "multi" => {
            ctx.next_token("multi")?; // Advance past "multi"
            let (_l_paren, _l_paren_column) = ctx.expect_token("multi", "(")?;
            let (k, k_column) = ctx
                .next_token("multi")?;
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
                    ctx.next_token("multi")?;
                }
                let (key, key_column) = ctx
                    .next_token("multi")?;

                let key = bitcoin::PublicKey::from_str(key).map_err(|e| {
                    ParseError::InvalidKey {
                        key,
                        position: key_column,
                        inner: "Invalid bitcoin::PublicKey key",
                    }
                })?;
                keys.push(KeyToken::new(KeyTokenInner::PublicKey(key)));
            }

            let (_r_paren, _r_paren_column) = ctx.expect_token("multi", ")")?;

            Ok(AST {
                position: column,
                fragment: Fragment::Multi { k, keys },
            })
        }

        "multi_a" => {
            ctx.next_token("multi_a")?; // Advance past "multi_a"
            let (_l_paren, _l_paren_column) = ctx.expect_token("multi_a", "(")?;
            let (k, k_column) = ctx
                .next_token("multi_a")?;
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
                    ctx.next_token("multi_a")?;
                }
                let (key, key_column) = ctx
                    .next_token("multi_a")?;
                let key = bitcoin::XOnlyPublicKey::from_str(key).map_err(|e| {
                    ParseError::InvalidXOnlyKey {
                        key,
                        position: key_column,
                    }
                })?;
                keys.push(KeyToken::new(KeyTokenInner::XOnlyPublicKey(key)));
            }

            let (_r_paren, _r_paren_column) = ctx.expect_token("multi_a", ")")?;

            Ok(AST {
                position: column,
                fragment: Fragment::MultiA { k, keys },
            })
        }

        _ => {
            // the top fragment cant be an identity

            if let Some((peek_token, _peek_token_column)) = ctx.peek_next_token() {
                if peek_token == ":" {
                    ctx.next_token("identity")?; // Advance past identity type

                    ctx.expect_token("identity", ":")?;

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

                    let mut node: AST = parse_internal(ctx)?;

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

            return parse_bool(ctx);
        }
    }

}

fn parse_bool<'a>(ctx: &mut ParserContext<'a>) -> Result<AST, ParseError<'a>> {
    let (token, column) = ctx.peek_token().ok_or(ParseError::UnexpectedEof {
        context: "parse_bool",
    })?;

    match token {
        "0" => {
            ctx.next_token("parse_bool")?;
            Ok(AST {
                position: column,
                fragment: Fragment::False,
            })
        }
        "1" => {
            ctx.next_token("parse_bool")?;
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
