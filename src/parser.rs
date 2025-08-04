use core::fmt::Debug;

use heapless::Vec;

use crate::lexer::{Identifier, Int, Lexer, LexerError, Position, Token};

//
// Nodes
//

#[derive(Debug)]
pub enum Fragment<'input> {
    // Basic Fragments
    /// 0
    False { position: Position },
    /// 1
    True { position: Position },

    // Key Fragments
    /// pk_k(key)
    PkK {
        position: Position,
        key: Identifier<'input>,
    },
    /// pk_h(key)
    PkH {
        position: Position,
        key: Identifier<'input>,
    },
    /// pk(key) = c:pk_k(key)
    Pk {
        position: Position,
        key: Identifier<'input>,
    },
    /// pkh(key) = c:pk_h(key)
    Pkh {
        position: Position,
        key: Identifier<'input>,
    },

    // Time fragments
    /// older(n)
    Older { position: Position, n: Int },
    /// after(n)
    After { position: Position, n: Int },

    // Hash Fragments
    /// sha256(h)
    Sha256 {
        position: Position,
        h: Identifier<'input>,
    },
    /// hash256(h)
    Hash256 {
        position: Position,
        h: Identifier<'input>,
    },
    /// ripemd160(h)
    Ripemd160 {
        position: Position,
        h: Identifier<'input>,
    },
    /// hash160(h)
    Hash160 {
        position: Position,
        h: Identifier<'input>,
    },

    // Logical Fragments
    /// andor(X,Y,Z)
    AndOr {
        position: Position,
        x: usize,
        y: usize,
        z: usize,
    },
    /// and_v(X,Y)
    AndV {
        position: Position,
        x: usize,
        y: usize,
    },
    /// and_b(X,Y)
    AndB {
        position: Position,
        x: usize,
        y: usize,
    },
    /// and_n(X,Y) = andor(X,Y,0)
    AndN {
        position: Position,
        x: usize,
        y: usize,
    },
    /// or_b(X,Z)
    OrB {
        position: Position,
        x: usize,
        z: usize,
    },
    /// or_c(X,Z)
    OrC {
        position: Position,
        x: usize,
        z: usize,
    },
    /// or_d(X,Z)
    OrD {
        position: Position,
        x: usize,
        z: usize,
    },
    /// or_i(X,Z)
    OrI {
        position: Position,
        x: usize,
        z: usize,
    },

    // Threshold Fragments
    /// thresh(k,X1,...,Xn)
    Thresh {
        position: Position,
        k: Int,
        xs: Vec<usize, 16>,
    },
    ///  multi(k,key1,...,keyn)
    /// (P2WSH only)
    Multi {
        position: Position,
        k: Int,
        keys: Vec<Identifier<'input>, 16>,
    },
    /// multi_a(k,key1,...,keyn)
    /// (Tapscript only)
    MultiA {
        position: Position,
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
    FragmentOverflow(Fragment<'input>),
    ThreshNotEnoughFragments(Position),
    MultiNotEnoughKeys(Position),
}

//
// Context
//

pub struct Context<'input, const FRAGMENT_BUFFER_SIZE: usize = 256> {
    lexer: &'input mut Lexer<'input>,

    fragments: Vec<Fragment<'input>, FRAGMENT_BUFFER_SIZE>,
    fragment_idx: usize,
}

impl<'input, const FRAGMENT_BUFFER_SIZE: usize> Context<'input, FRAGMENT_BUFFER_SIZE> {
    pub fn new(lexer: &'input mut Lexer<'input>) -> Self {
        Self {
            lexer,
            fragments: Vec::new(),
            fragment_idx: 0,
        }
    }

    pub fn push_fragment(
        &mut self,
        fragment: Fragment<'input>,
    ) -> Result<usize, ParserError<'input>> {
        let idx = self.fragment_idx;
        self.fragments
            .push(fragment)
            .map_err(|it| ParserError::FragmentOverflow(it))?;

        self.fragment_idx += 1;
        Ok(idx)
    }

    pub fn get_fragment(&self, idx: usize) -> Option<&Fragment<'input>> {
        self.fragments.get(idx)
    }

    pub fn visit_fragment<V: FragmentVisitor<'input, FRAGMENT_BUFFER_SIZE>>(
        &self,
        fragment: &Fragment<'input>,
        visitor: &mut V,
    ) {
        visitor.visit_fragment(fragment, self);
    }
}

//
// FragmentVisitor trait
//

pub trait FragmentVisitor<'input, const FRAGMENT_BUFFER_SIZE: usize = 256> {
    fn visit_fragment(
        &mut self,
        fragment: &Fragment<'input>,
        ctx: &Context<'input, FRAGMENT_BUFFER_SIZE>,
    );

    fn visit_fragment_by_idx(&mut self, idx: usize, ctx: &Context<'input, FRAGMENT_BUFFER_SIZE>) {
        if let Some(fragment) = ctx.get_fragment(idx) {
            self.visit_fragment(fragment, ctx);
        }
    }
}

//
// Parsing functions
//

pub fn parse<'input, const FRAGMENT_BUFFER_SIZE: usize>(
    ctx: &mut Context<'input, FRAGMENT_BUFFER_SIZE>,
) -> Result<Fragment<'input>, ParserError<'input>> {
    parse_logical_fragment(ctx)
}

fn parse_logical_fragment<'input, const FRAGMENT_BUFFER_SIZE: usize>(
    ctx: &mut Context<'input, FRAGMENT_BUFFER_SIZE>,
) -> Result<Fragment<'input>, ParserError<'input>> {
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

                return Ok(Fragment::AndOr {
                    position: identifier.position.clone(),
                    x: ctx.push_fragment(x)?,
                    y: ctx.push_fragment(y)?,
                    z: ctx.push_fragment(z)?,
                });
            }
            "and_v" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let x = parse_logical_fragment(ctx)?;
                expect_token(ctx, "Comma", |t| matches!(t, Token::Comma(_)))?;

                let y = parse_logical_fragment(ctx)?;
                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Fragment::AndV {
                    position: identifier.position.clone(),
                    x: ctx.push_fragment(x)?,
                    y: ctx.push_fragment(y)?,
                });
            }
            "and_b" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let x = parse_logical_fragment(ctx)?;
                expect_token(ctx, "Comma", |t| matches!(t, Token::Comma(_)))?;

                let y = parse_logical_fragment(ctx)?;
                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Fragment::AndB {
                    position: identifier.position.clone(),
                    x: ctx.push_fragment(x)?,
                    y: ctx.push_fragment(y)?,
                });
            }
            "and_n" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let x = parse_logical_fragment(ctx)?;
                expect_token(ctx, "Comma", |t| matches!(t, Token::Comma(_)))?;

                let y = parse_logical_fragment(ctx)?;
                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Fragment::AndN {
                    position: identifier.position.clone(),
                    x: ctx.push_fragment(x)?,
                    y: ctx.push_fragment(y)?,
                });
            }
            "or_b" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let x = parse_logical_fragment(ctx)?;
                expect_token(ctx, "Comma", |t| matches!(t, Token::Comma(_)))?;

                let z = parse_logical_fragment(ctx)?;
                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Fragment::OrB {
                    position: identifier.position.clone(),
                    x: ctx.push_fragment(x)?,
                    z: ctx.push_fragment(z)?,
                });
            }
            "or_c" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let x = parse_logical_fragment(ctx)?;
                expect_token(ctx, "Comma", |t| matches!(t, Token::Comma(_)))?;

                let z = parse_logical_fragment(ctx)?;
                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Fragment::OrC {
                    position: identifier.position.clone(),
                    x: ctx.push_fragment(x)?,
                    z: ctx.push_fragment(z)?,
                });
            }
            "or_d" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let x = parse_logical_fragment(ctx)?;
                expect_token(ctx, "Comma", |t| matches!(t, Token::Comma(_)))?;

                let z = parse_logical_fragment(ctx)?;
                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Fragment::OrD {
                    position: identifier.position.clone(),
                    x: ctx.push_fragment(x)?,
                    z: ctx.push_fragment(z)?,
                });
            }
            "or_i" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let x = parse_logical_fragment(ctx)?;
                expect_token(ctx, "Comma", |t| matches!(t, Token::Comma(_)))?;

                let z = parse_logical_fragment(ctx)?;
                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Fragment::OrI {
                    position: identifier.position.clone(),
                    x: ctx.push_fragment(x)?,
                    z: ctx.push_fragment(z)?,
                });
            }
            "thresh" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let k = expect_int(ctx)?;

                expect_token(ctx, "Comma", |t| matches!(t, Token::Comma(_)))?;

                let mut xs = Vec::new();

                // Parse fragments until we hit the closing parenthesis
                loop {
                    let fragment = parse_logical_fragment(ctx)?;
                    xs.push(ctx.push_fragment(fragment)?).unwrap();

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

                return Ok(Fragment::Thresh {
                    position: identifier.position.clone(),
                    k,
                    xs: xs,
                });
            }
            _ => {}
        },
        _ => {}
    }
    parse_multi_fragment(next_token, ctx)
}

fn parse_multi_fragment<'input, const FRAGMENT_BUFFER_SIZE: usize>(
    next_token: Token<'input>,
    ctx: &mut Context<'input, FRAGMENT_BUFFER_SIZE>,
) -> Result<Fragment<'input>, ParserError<'input>> {
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

                return Ok(Fragment::Multi {
                    position: identifier.position.clone(),
                    k,
                    keys: keys,
                });
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

                return Ok(Fragment::MultiA {
                    position: identifier.position.clone(),
                    k,
                    keys: keys,
                });
            }
            _ => {}
        },
        _ => {}
    }
    parse_key_fragment(next_token, ctx)
}

fn parse_key_fragment<'input, const FRAGMENT_BUFFER_SIZE: usize>(
    next_token: Token<'input>,
    ctx: &mut Context<'input, FRAGMENT_BUFFER_SIZE>,
) -> Result<Fragment<'input>, ParserError<'input>> {
    match &next_token {
        Token::Identifier(identifier) => match identifier.value {
            "pk_k" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let key = expect_identifier(ctx)?;

                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Fragment::PkK {
                    position: identifier.position.clone(),
                    key,
                });
            }
            "pk_h" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let key = expect_identifier(ctx)?;

                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Fragment::PkH {
                    position: identifier.position.clone(),
                    key,
                });
            }
            "pk" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let key = expect_identifier(ctx)?;

                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Fragment::Pk {
                    position: identifier.position.clone(),
                    key,
                });
            }
            "pkh" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let key = expect_identifier(ctx)?;

                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Fragment::Pkh {
                    position: identifier.position.clone(),
                    key,
                });
            }
            "older" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let n = expect_int(ctx)?;

                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Fragment::Older {
                    position: identifier.position.clone(),
                    n,
                });
            }
            "after" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let n = expect_int(ctx)?;

                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Fragment::After {
                    position: identifier.position.clone(),
                    n,
                });
            }
            "sha256" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let h = expect_identifier(ctx)?;

                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Fragment::Sha256 {
                    position: identifier.position.clone(),
                    h,
                });
            }
            "hash256" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let h = expect_identifier(ctx)?;

                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Fragment::Hash256 {
                    position: identifier.position.clone(),
                    h,
                });
            }
            "ripemd160" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let h = expect_identifier(ctx)?;

                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Fragment::Ripemd160 {
                    position: identifier.position.clone(),
                    h,
                });
            }
            "hash160" => {
                expect_token(ctx, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                let h = expect_identifier(ctx)?;

                expect_token(ctx, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                return Ok(Fragment::Hash160 {
                    position: identifier.position.clone(),
                    h,
                });
            }
            _ => {}
        },
        _ => {}
    }
    parse_basic_fragment::<FRAGMENT_BUFFER_SIZE>(next_token)
}

fn parse_basic_fragment<'input, const FRAGMENT_BUFFER_SIZE: usize>(
    next_token: Token<'input>,
) -> Result<Fragment<'input>, ParserError<'input>> {
    match next_token {
        Token::Bool { position, value } => {
            if value {
                Ok(Fragment::True { position })
            } else {
                Ok(Fragment::False { position })
            }
        }
        invalid_token => Err(ParserError::UnexpectedToken {
            expected: "Bool",
            found: invalid_token,
        }),
    }
}

fn parse_next_token<'input, const FRAGMENT_BUFFER_SIZE: usize>(
    ctx: &mut Context<'input, FRAGMENT_BUFFER_SIZE>,
) -> Result<Token<'input>, ParserError<'input>> {
    let token_result = ctx.lexer.next_token();
    match token_result {
        Ok(Token::Eof(position)) => Err(ParserError::UnexpectedEof(position)),
        Ok(token) => Ok(token),
        Err(error) => Err(ParserError::LexerError(error))?,
    }
}

fn expect_token<'input, const FRAGMENT_BUFFER_SIZE: usize>(
    ctx: &mut Context<'input, FRAGMENT_BUFFER_SIZE>,
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

fn expect_identifier<'input, const FRAGMENT_BUFFER_SIZE: usize>(
    ctx: &mut Context<'input, FRAGMENT_BUFFER_SIZE>,
) -> Result<Identifier<'input>, ParserError<'input>> {
    let token = expect_token(ctx, "Identifier", |t| matches!(t, Token::Identifier(_)))?;
    if let Token::Identifier(identifier) = token {
        Ok(identifier)
    } else {
        unreachable!()
    }
}

fn expect_int<'input, const FRAGMENT_BUFFER_SIZE: usize>(
    ctx: &mut Context<'input, FRAGMENT_BUFFER_SIZE>,
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
