use core::fmt::Debug;

use heapless::Vec;

use crate::{
    lexer::{Identifier, Int, Lexer, LexerError, Position, Token},
    visitor::NodeVisitor,
};

///
/// Miniscript basic expression types
///

#[derive(Debug, Clone, PartialEq)]
pub enum MiniscriptType {
    B, // Base
    V, // Verify
    K, // Key
    W, // Wrapped
}

#[derive(Debug)]
pub struct TypeInfo {
    base_type: MiniscriptType,
    // pub properties: TypeProperties,
}

impl TypeInfo {
    pub fn new(base_type: MiniscriptType) -> Self {
        Self { base_type }
    }

    pub fn base_type(&self) -> &MiniscriptType {
        &self.base_type
    }
}

//
// AST Wrapper Nodes with position and type info
//

#[derive(Debug)]
pub struct Node<'input> {
    pub position: Position,
    pub fragment: Fragment<'input>,
    pub type_info: TypeInfo,
}

impl<'input> Node<'input> {
    pub fn new(
        position: Position,
        fragment: Fragment<'input>,
        miniscript_type: MiniscriptType,
    ) -> Self {
        Self {
            position,
            fragment,
            type_info: TypeInfo::new(miniscript_type),
        }
    }
}

///
/// AST Fragments
///

#[derive(Debug)]
pub enum Fragment<'input> {
    // Basic Fragments
    /// 0
    False,
    /// 1
    True,

    // Key Fragments
    /// pk_k(key)
    PkK { key: Identifier<'input> },
    /// pk_h(key)
    PkH { key: Identifier<'input> },
    /// pk(key) = c:pk_k(key)
    Pk { key: Identifier<'input> },
    /// pkh(key) = c:pk_h(key)
    Pkh { key: Identifier<'input> },

    // Time fragments
    /// older(n)
    Older { n: Int },
    /// after(n)
    After { n: Int },

    // Hash Fragments
    /// sha256(h)
    Sha256 { h: Identifier<'input> },
    /// hash256(h)
    Hash256 { h: Identifier<'input> },
    /// ripemd160(h)
    Ripemd160 { h: Identifier<'input> },
    /// hash160(h)
    Hash160 { h: Identifier<'input> },

    // Logical Fragments
    /// andor(X,Y,Z)
    AndOr { x: usize, y: usize, z: usize },
    /// and_v(X,Y)
    AndV { x: usize, y: usize },
    /// and_b(X,Y)
    AndB { x: usize, y: usize },
    /// and_n(X,Y) = andor(X,Y,0)
    AndN { x: usize, y: usize },
    /// or_b(X,Z)
    OrB { x: usize, z: usize },
    /// or_c(X,Z)
    OrC { x: usize, z: usize },
    /// or_d(X,Z)
    OrD { x: usize, z: usize },
    /// or_i(X,Z)
    OrI { x: usize, z: usize },

    // Threshold Fragments
    /// thresh(k,X1,...,Xn)
    Thresh { k: Int, xs: Vec<usize, 16> },
    ///  multi(k,key1,...,keyn)
    /// (P2WSH only)
    Multi {
        k: Int,
        keys: Vec<Identifier<'input>, 16>,
    },
    /// multi_a(k,key1,...,keyn)
    /// (Tapscript only)
    MultiA {
        k: Int,
        keys: Vec<Identifier<'input>, 16>,
    },
}

//
// ParserError
//

#[derive(Debug)]
pub enum ParserError<'input> {
    LexerError(LexerError),
    UnexpectedEof(Position),
    UnexpectedToken {
        expected: &'static str,
        found: Token<'input>,
    },
    NodeOverflow(Node<'input>),
    ThreshNotEnoughFragments(Position),
    MultiNotEnoughKeys(Position),
}

//
// Context
//

pub struct Context<'input, const NODE_BUFFER_SIZE: usize = 256> {
    lexer: &'input mut Lexer<'input>,

    nodes: Vec<Node<'input>, NODE_BUFFER_SIZE>,
    node_idx: usize,
}

impl<'input, const NODE_BUFFER_SIZE: usize> Context<'input, NODE_BUFFER_SIZE> {
    pub fn new(lexer: &'input mut Lexer<'input>) -> Self {
        Self {
            lexer,
            nodes: Vec::new(),
            node_idx: 0,
        }
    }

    pub fn push_node(&mut self, node: Node<'input>) -> Result<usize, ParserError<'input>> {
        let idx = self.node_idx;
        self.nodes
            .push(node)
            .map_err(|it| ParserError::NodeOverflow(it))?;

        self.node_idx += 1;
        Ok(idx)
    }

    pub(crate) fn get_node(&self, idx: usize) -> Option<&Node<'input>> {
        self.nodes.get(idx)
    }

    pub fn visit_node<V: NodeVisitor<'input, NODE_BUFFER_SIZE>>(
        &self,
        node: &Node<'input>,
        visitor: &mut V,
    ) -> Result<(), V::Error> {
        visitor.visit_node(node, self)
    }
}

//
// Parsing functions
//

pub fn parse<'input, const NODE_BUFFER_SIZE: usize>(
    ctx: &mut Context<'input, NODE_BUFFER_SIZE>,
) -> Result<Node<'input>, ParserError<'input>> {
    parse_logical_fragment(ctx)
}

fn parse_logical_fragment<'input, const NODE_BUFFER_SIZE: usize>(
    ctx: &mut Context<'input, NODE_BUFFER_SIZE>,
) -> Result<Node<'input>, ParserError<'input>> {
    let next_token = parse_next_token(ctx)?;
    match &next_token {
        Token::Identifier(identifier) => match identifier.value {
            "andor" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let x = parse_logical_fragment(ctx)?;
                expect_token(ctx, "Comma", |t| matches!(t, Token::Comma(_)))?;

                let y = parse_logical_fragment(ctx)?;
                expect_token(ctx, "Comma", |t| matches!(t, Token::Comma(_)))?;

                let z = parse_logical_fragment(ctx)?;
                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                // The type is same as Y/Z
                let miniscript_type = y.type_info.base_type.clone();

                return Ok(Node::new(
                    identifier.position.clone(),
                    Fragment::AndOr {
                        x: ctx.push_node(x)?,
                        y: ctx.push_node(y)?,
                        z: ctx.push_node(z)?,
                    },
                    miniscript_type,
                ));
            }
            "and_v" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let x = parse_logical_fragment(ctx)?;
                expect_token(ctx, "Comma", |t| matches!(t, Token::Comma(_)))?;

                let y = parse_logical_fragment(ctx)?;
                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                // The type is same as Y
                let miniscript_type = y.type_info.base_type.clone();

                return Ok(Node::new(
                    identifier.position.clone(),
                    Fragment::AndV {
                        x: ctx.push_node(x)?,
                        y: ctx.push_node(y)?,
                    },
                    miniscript_type,
                ));
            }
            "and_b" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let x = parse_logical_fragment(ctx)?;
                expect_token(ctx, "Comma", |t| matches!(t, Token::Comma(_)))?;

                let y = parse_logical_fragment(ctx)?;
                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Node::new(
                    identifier.position.clone(),
                    Fragment::AndB {
                        x: ctx.push_node(x)?,
                        y: ctx.push_node(y)?,
                    },
                    MiniscriptType::B,
                ));
            }
            "and_n" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let x = parse_logical_fragment(ctx)?;
                expect_token(ctx, "Comma", |t| matches!(t, Token::Comma(_)))?;

                let y = parse_logical_fragment(ctx)?;
                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Node::new(
                    identifier.position.clone(),
                    Fragment::AndN {
                        x: ctx.push_node(x)?,
                        y: ctx.push_node(y)?,
                    },
                    MiniscriptType::B, // TODO: Check if this is correct
                ));
            }
            "or_b" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let x = parse_logical_fragment(ctx)?;
                expect_token(ctx, "Comma", |t| matches!(t, Token::Comma(_)))?;

                let z = parse_logical_fragment(ctx)?;
                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Node::new(
                    identifier.position.clone(),
                    Fragment::OrB {
                        x: ctx.push_node(x)?,
                        z: ctx.push_node(z)?,
                    },
                    MiniscriptType::B,
                ));
            }
            "or_c" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let x = parse_logical_fragment(ctx)?;
                expect_token(ctx, "Comma", |t| matches!(t, Token::Comma(_)))?;

                let z = parse_logical_fragment(ctx)?;
                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Node::new(
                    identifier.position.clone(),
                    Fragment::OrC {
                        x: ctx.push_node(x)?,
                        z: ctx.push_node(z)?,
                    },
                    MiniscriptType::V,
                ));
            }
            "or_d" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let x = parse_logical_fragment(ctx)?;
                expect_token(ctx, "Comma", |t| matches!(t, Token::Comma(_)))?;

                let z = parse_logical_fragment(ctx)?;
                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Node::new(
                    identifier.position.clone(),
                    Fragment::OrD {
                        x: ctx.push_node(x)?,
                        z: ctx.push_node(z)?,
                    },
                    MiniscriptType::B,
                ));
            }
            "or_i" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let x = parse_logical_fragment(ctx)?;
                expect_token(ctx, "Comma", |t| matches!(t, Token::Comma(_)))?;

                let z = parse_logical_fragment(ctx)?;
                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                // The type is same as X/Z
                let miniscript_type = x.type_info.base_type.clone();

                return Ok(Node::new(
                    identifier.position.clone(),
                    Fragment::OrI {
                        x: ctx.push_node(x)?,
                        z: ctx.push_node(z)?,
                    },
                    miniscript_type,
                ));
            }
            "thresh" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let k = expect_int(ctx)?;

                expect_token(ctx, "Comma", |t| matches!(t, Token::Comma(_)))?;

                let mut xs = Vec::new();

                // Parse fragments until we hit the closing parenthesis
                loop {
                    let fragment = parse_logical_fragment(ctx)?;
                    xs.push(ctx.push_node(fragment)?).unwrap();

                    // Check what comes next
                    let next_token = parse_next_token(ctx)?;
                    match next_token {
                        Token::RightParen(_) => {
                            // End of thresh
                            break;
                        }
                        Token::Comma(_) => {
                            // Continue with next fragment
                            continue;
                        }
                        _ => {
                            return Err(ParserError::UnexpectedToken {
                                expected: "Comma or RightParen",
                                found: next_token,
                            });
                        }
                    }
                }

                // Validate that we have at least one fragment
                if xs.is_empty() {
                    return Err(ParserError::ThreshNotEnoughFragments(
                        identifier.position.clone(),
                    ));
                }

                return Ok(Node::new(
                    identifier.position.clone(),
                    Fragment::Thresh { k, xs: xs },
                    MiniscriptType::B,
                ));
            }
            _ => {}
        },
        _ => {}
    }
    parse_multi_fragment(next_token, ctx)
}

fn parse_multi_fragment<'input, const NODE_BUFFER_SIZE: usize>(
    next_token: Token<'input>,
    ctx: &mut Context<'input, NODE_BUFFER_SIZE>,
) -> Result<Node<'input>, ParserError<'input>> {
    match &next_token {
        Token::Identifier(identifier) => match identifier.value {
            "multi" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let k = expect_int(ctx)?;

                expect_token(ctx, "Comma", |t| matches!(t, Token::Comma(_)))?;

                let mut keys = Vec::new();

                // Parse first key
                let first_key = expect_identifier(ctx)?;
                keys.push(first_key).unwrap();

                // Parse remaining keys
                loop {
                    let next_token = parse_next_token(ctx)?;
                    match next_token {
                        Token::RightParen(_) => {
                            // End of multi
                            break;
                        }
                        Token::Comma(_) => {
                            // Continue with next key
                            let key = expect_identifier(ctx)?;
                            keys.push(key).unwrap();
                        }
                        _ => {
                            return Err(ParserError::UnexpectedToken {
                                expected: "Comma or RightParen",
                                found: next_token,
                            });
                        }
                    }
                }

                // Validate that we have at least one key
                if keys.is_empty() {
                    return Err(ParserError::MultiNotEnoughKeys(identifier.position.clone()));
                }

                return Ok(Node::new(
                    identifier.position.clone(),
                    Fragment::Multi { k, keys: keys },
                    MiniscriptType::B,
                ));
            }
            "multi_a" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let k = expect_int(ctx)?;

                expect_token(ctx, "Comma", |t| matches!(t, Token::Comma(_)))?;

                let mut keys = Vec::new();

                // Parse first key
                let first_key = expect_identifier(ctx)?;
                keys.push(first_key).unwrap();

                // Parse remaining keys
                loop {
                    let next_token = parse_next_token(ctx)?;
                    match next_token {
                        Token::RightParen(_) => {
                            // End of multi_a
                            break;
                        }
                        Token::Comma(_) => {
                            // Continue with next key
                            let key = expect_identifier(ctx)?;
                            keys.push(key).unwrap();
                        }
                        _ => {
                            return Err(ParserError::UnexpectedToken {
                                expected: "Comma or RightParen",
                                found: next_token,
                            });
                        }
                    }
                }

                // Validate that we have at least one key
                if keys.is_empty() {
                    return Err(ParserError::MultiNotEnoughKeys(identifier.position.clone()));
                }

                return Ok(Node::new(
                    identifier.position.clone(),
                    Fragment::MultiA { k, keys: keys },
                    MiniscriptType::B,
                ));
            }
            _ => {}
        },
        _ => {}
    }
    parse_key_fragment(next_token, ctx)
}

fn parse_key_fragment<'input, const NODE_BUFFER_SIZE: usize>(
    next_token: Token<'input>,
    ctx: &mut Context<'input, NODE_BUFFER_SIZE>,
) -> Result<Node<'input>, ParserError<'input>> {
    match &next_token {
        Token::Identifier(identifier) => match identifier.value {
            "pk_k" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let key = expect_identifier(ctx)?;

                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Node::new(
                    identifier.position.clone(),
                    Fragment::PkK { key },
                    MiniscriptType::K,
                ));
            }
            "pk_h" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let key = expect_identifier(ctx)?;

                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Node::new(
                    identifier.position.clone(),
                    Fragment::PkH { key },
                    MiniscriptType::K,
                ));
            }
            "pk" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let key = expect_identifier(ctx)?;

                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Node::new(
                    identifier.position.clone(),
                    Fragment::Pk { key },
                    MiniscriptType::K,
                ));
            }
            "pkh" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let key = expect_identifier(ctx)?;

                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Node::new(
                    identifier.position.clone(),
                    Fragment::Pkh { key },
                    MiniscriptType::K,
                ));
            }
            "older" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let n = expect_int(ctx)?;

                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Node::new(
                    identifier.position.clone(),
                    Fragment::Older { n },
                    MiniscriptType::B,
                ));
            }
            "after" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let n = expect_int(ctx)?;

                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Node::new(
                    identifier.position.clone(),
                    Fragment::After { n },
                    MiniscriptType::B,
                ));
            }
            "sha256" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let h = expect_identifier(ctx)?;

                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Node::new(
                    identifier.position.clone(),
                    Fragment::Sha256 { h },
                    MiniscriptType::B,
                ));
            }
            "hash256" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let h = expect_identifier(ctx)?;

                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Node::new(
                    identifier.position.clone(),
                    Fragment::Hash256 { h },
                    MiniscriptType::B,
                ));
            }
            "ripemd160" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let h = expect_identifier(ctx)?;

                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Node::new(
                    identifier.position.clone(),
                    Fragment::Ripemd160 { h },
                    MiniscriptType::B,
                ));
            }
            "hash160" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let h = expect_identifier(ctx)?;

                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Node::new(
                    identifier.position.clone(),
                    Fragment::Hash160 { h },
                    MiniscriptType::B,
                ));
            }
            _ => {}
        },
        _ => {}
    }
    parse_basic_fragment::<NODE_BUFFER_SIZE>(next_token)
}

fn parse_basic_fragment<'input, const NODE_BUFFER_SIZE: usize>(
    next_token: Token<'input>,
) -> Result<Node<'input>, ParserError<'input>> {
    match next_token {
        Token::Bool { position, value } => {
            if value {
                Ok(Node::new(position, Fragment::True, MiniscriptType::B))
            } else {
                Ok(Node::new(position, Fragment::False, MiniscriptType::B))
            }
        }
        invalid_token => Err(ParserError::UnexpectedToken {
            expected: "Bool",
            found: invalid_token,
        }),
    }
}

fn parse_next_token<'input, const NODE_BUFFER_SIZE: usize>(
    ctx: &mut Context<'input, NODE_BUFFER_SIZE>,
) -> Result<Token<'input>, ParserError<'input>> {
    let token_result = ctx.lexer.next_token();
    match token_result {
        Ok(Token::Eof(position)) => Err(ParserError::UnexpectedEof(position)),
        Ok(token) => Ok(token),
        Err(error) => Err(ParserError::LexerError(error))?,
    }
}

fn expect_token<'input, const NODE_BUFFER_SIZE: usize>(
    ctx: &mut Context<'input, NODE_BUFFER_SIZE>,
    expected: &'static str,
    token_matcher: impl Fn(&Token<'input>) -> bool,
) -> Result<Token<'input>, ParserError<'input>> {
    let token = parse_next_token(ctx)?;
    if token_matcher(&token) {
        Ok(token)
    } else {
        Err(ParserError::UnexpectedToken {
            expected,
            found: token,
        })
    }
}

fn expect_identifier<'input, const NODE_BUFFER_SIZE: usize>(
    ctx: &mut Context<'input, NODE_BUFFER_SIZE>,
) -> Result<Identifier<'input>, ParserError<'input>> {
    let token = expect_token(ctx, "Identifier", |t| matches!(t, Token::Identifier(_)))?;
    if let Token::Identifier(identifier) = token {
        Ok(identifier)
    } else {
        unreachable!()
    }
}

fn expect_int<'input, const NODE_BUFFER_SIZE: usize>(
    ctx: &mut Context<'input, NODE_BUFFER_SIZE>,
) -> Result<Int, ParserError<'input>> {
    let token = expect_token(ctx, "Int", |t| {
        matches!(t, Token::Int(_) | Token::Bool { .. })
    })?;
    match token {
        Token::Int(int) => Ok(int),
        Token::Bool { position, value } => Ok(Int {
            position,
            value: if value { 1 } else { 0 },
        }),
        _ => unreachable!(),
    }
}
