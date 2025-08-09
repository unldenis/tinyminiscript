use alloc::{boxed::Box, vec::Vec};
use core::fmt::Debug;

// AST Visitor

pub trait ASTVisitor<T> {
    type Error;

    fn visit_ast(&mut self, node: &AST) -> Result<T, Self::Error>;
}

// Position
pub type Position = usize;

// AST

#[derive(Debug)]
pub struct AST<'a> {
    pub position: Position,
    pub fragment: Fragment<'a>,
}

#[derive(Debug)]
pub enum Fragment<'a> {
    // Basic Fragments
    /// 0
    False,
    /// 1
    True,

    // Key Fragments
    /// pk_k(key)
    PkK { key: &'a str },
    /// pk_h(key)
    PkH { key: &'a str },

    // Time fragments
    /// older(n)
    Older { n: i64 },
    /// after(n)
    After { n: i64 },

    // Hash Fragments
    /// sha256(h)
    Sha256 { h: &'a str },
    /// hash256(h)
    Hash256 { h: &'a str },
    /// ripemd160(h)
    Ripemd160 { h: &'a str },
    /// hash160(h)
    Hash160 { h: &'a str },

    // Logical Fragments
    /// andor(X,Y,Z)
    AndOr {
        x: Box<AST<'a>>,
        y: Box<AST<'a>>,
        z: Box<AST<'a>>,
    },
    /// and_v(X,Y)
    AndV { x: Box<AST<'a>>, y: Box<AST<'a>> },
    /// and_b(X,Y)
    AndB { x: Box<AST<'a>>, y: Box<AST<'a>> },

    // /// and_n(X,Y) = andor(X,Y,0)
    // AndN { x: Box<AST>, y: Box<AST> },
    /// or_b(X,Z)
    OrB { x: Box<AST<'a>>, z: Box<AST<'a>> },
    /// or_c(X,Z)
    OrC { x: Box<AST<'a>>, z: Box<AST<'a>> },
    /// or_d(X,Z)
    OrD { x: Box<AST<'a>>, z: Box<AST<'a>> },
    /// or_i(X,Z)
    OrI { x: Box<AST<'a>>, z: Box<AST<'a>> },

    // Threshold Fragments
    /// thresh(k,X1,...,Xn)
    Thresh { k: i32, xs: Vec<Box<AST<'a>>> },
    ///  multi(k,key1,...,keyn)
    /// (P2WSH only)
    Multi { k: i32, keys: Vec<&'a str> },
    /// multi_a(k,key1,...,keyn)
    /// (Tapscript only)
    MultiA { k: i32, keys: Vec<&'a str> },

    Identity {
        identity_type: IdentityType,
        x: Box<AST<'a>>,
    },
}

#[derive(Debug)]
pub enum IdentityType {
    A,
    S,
    C,
    D,
    V,
    J,
    N,
}

// Optimized tokenization using string slices instead of owned strings
fn split_string_with_columns<'a, F>(s: &'a str, is_separator: F) -> Vec<(&'a str, usize)>
where
    F: Fn(char) -> bool,
{
    // Pre-allocate with estimated capacity to reduce reallocations
    let estimated_tokens = s.len() / 3 + 1; // Rough estimate
    let mut result = Vec::with_capacity(estimated_tokens);
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

#[derive(Debug)]
pub enum ParseError<'a> {
    UnexpectedEof {
        context: &'static str,
    },
    UnexpectedToken {
        expected: &'static str,
        found: (&'a str, usize),
    },
}

struct Context<'a> {
    tokens: Vec<(&'a str, usize)>,
    current_token: usize,
}

impl<'a> Context<'a> {
    fn new(input: &'a str) -> Self {
        let tokens =
            split_string_with_columns(input, |c| c == '(' || c == ')' || c == ',' || c == ':');
        Self {
            tokens,
            current_token: 0,
        }
    }

    // return the next token
    fn next_token(&mut self) -> Option<(&'a str, usize)> {
        if self.current_token < self.tokens.len() {
            let token = self.tokens[self.current_token];
            self.current_token += 1;
            Some(token)
        } else {
            None
        }
    }

    fn peek_token(&self) -> Option<(&'a str, usize)> {
        if self.current_token < self.tokens.len() {
            Some(self.tokens[self.current_token])
        } else {
            None
        }
    }

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

    fn peek_next_token(&self) -> Option<(&'a str, usize)> {
        if self.current_token + 1 < self.tokens.len() {
            Some(self.tokens[self.current_token + 1])
        } else {
            None
        }
    }
}

pub fn parse<'a>(input: &'a str) -> Result<AST<'a>, ParseError<'a>> {
    let mut ctx = Context::new(input);
    parse_internal(&mut ctx)
}

fn parse_internal<'a>(ctx: &mut Context<'a>) -> Result<AST<'a>, ParseError<'a>> {
    let (token, column) = ctx
        .peek_token()
        .ok_or(ParseError::UnexpectedEof { context: "parse" })?;

    match token {
        "0" => {
            ctx.next_token(); // Advance past "0"
            Ok(AST {
                position: column,
                fragment: Fragment::False,
            })
        }
        "1" => {
            ctx.next_token(); // Advance past "1"
            Ok(AST {
                position: column,
                fragment: Fragment::True,
            })
        }
        "pk_k" => {
            ctx.next_token(); // Advance past "pk_k"
            let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
            let (key, _key_column) = ctx
                .next_token()
                .ok_or(ParseError::UnexpectedEof { context: "pk_k" })?;

            let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

            Ok(AST {
                position: column,
                fragment: Fragment::PkK { key },
            })
        }
        "pk_h" => {
            ctx.next_token(); // Advance past "pk_h"
            let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
            let (key, _key_column) = ctx
                .next_token()
                .ok_or(ParseError::UnexpectedEof { context: "pk_h" })?;

            let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

            Ok(AST {
                position: column,
                fragment: Fragment::PkH { key },
            })
        }
        "pk" => {
            // pk(key) = c:pk_k(key)

            ctx.next_token(); // Advance past "pk"
            let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
            let (key, _key_column) = ctx
                .next_token()
                .ok_or(ParseError::UnexpectedEof { context: "pk" })?;

            let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

            let mut ast = AST {
                position: column,
                fragment: Fragment::PkK { key },
            };

            // wrap in c: identity
            ast = AST {
                position: column,
                fragment: Fragment::Identity {
                    identity_type: IdentityType::C,
                    x: Box::new(ast),
                },
            };
            Ok(ast)
        }
        "pkh" => {
            // pkh(key) = c:pk_h(key)

            ctx.next_token(); // Advance past "pkh"
            let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
            let (key, _key_column) = ctx
                .next_token()
                .ok_or(ParseError::UnexpectedEof { context: "pkh" })?;

            let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

            let mut ast = AST {
                position: column,
                fragment: Fragment::PkH { key },
            };

            // wrap in c: identity
            ast = AST {
                position: column,
                fragment: Fragment::Identity {
                    identity_type: IdentityType::C,
                    x: Box::new(ast),
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

            // check if n is i64
            let n = n.parse::<i64>().map_err(|_| ParseError::UnexpectedToken {
                expected: "i64",
                found: (n, n_column),
            })?;

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

            // check if n is i64
            let n = n.parse::<i64>().map_err(|_| ParseError::UnexpectedToken {
                expected: "i64",
                found: (n, n_column),
            })?;

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

            Ok(AST {
                position: column,
                fragment: Fragment::Hash160 { h },
            })
        }

        "andor" => {
            ctx.next_token(); // Advance past "andor"

            let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;

            let x = parse_internal(ctx)?;

            let (_comma, _comma_column) = ctx.expect_token(",")?;

            let y = parse_internal(ctx)?;

            let (_comma, _comma_column) = ctx.expect_token(",")?;

            let z = parse_internal(ctx)?;

            let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

            Ok(AST {
                position: column,
                fragment: Fragment::AndOr {
                    x: Box::new(x),
                    y: Box::new(y),
                    z: Box::new(z),
                },
            })
        }

        "and_v" => {
            ctx.next_token(); // Advance past "and_v"
            let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
            let x = parse_internal(ctx)?;
            let (_comma, _comma_column) = ctx.expect_token(",")?;
            let y = parse_internal(ctx)?;
            let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

            Ok(AST {
                position: column,
                fragment: Fragment::AndV {
                    x: Box::new(x),
                    y: Box::new(y),
                },
            })
        }

        "and_b" => {
            ctx.next_token(); // Advance past "and_b"
            let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
            let x = parse_internal(ctx)?;
            let (_comma, _comma_column) = ctx.expect_token(",")?;
            let y = parse_internal(ctx)?;
            let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

            Ok(AST {
                position: column,
                fragment: Fragment::AndB {
                    x: Box::new(x),
                    y: Box::new(y),
                },
            })
        }

        "and_n" => {
            // and_n(X,Y) = andor(X,Y,0)

            ctx.next_token(); // Advance past "and_n"
            let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
            let x = parse_internal(ctx)?;
            let (_comma, _comma_column) = ctx.expect_token(",")?;
            let y = parse_internal(ctx)?;
            let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

            let ast = AST {
                position: column,
                fragment: Fragment::AndOr {
                    x: Box::new(x),
                    y: Box::new(y),
                    z: Box::new(AST {
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
            let x = parse_internal(ctx)?;
            let (_comma, _comma_column) = ctx.expect_token(",")?;
            let z = parse_internal(ctx)?;
            let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

            Ok(AST {
                position: column,
                fragment: Fragment::OrB {
                    x: Box::new(x),
                    z: Box::new(z),
                },
            })
        }

        "or_c" => {
            ctx.next_token(); // Advance past "or_c"
            let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
            let x = parse_internal(ctx)?;
            let (_comma, _comma_column) = ctx.expect_token(",")?;
            let z = parse_internal(ctx)?;
            let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

            Ok(AST {
                position: column,
                fragment: Fragment::OrC {
                    x: Box::new(x),
                    z: Box::new(z),
                },
            })
        }

        "or_d" => {
            ctx.next_token(); // Advance past "or_d"
            let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
            let x = parse_internal(ctx)?;
            let (_comma, _comma_column) = ctx.expect_token(",")?;
            let z = parse_internal(ctx)?;
            let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

            Ok(AST {
                position: column,
                fragment: Fragment::OrD {
                    x: Box::new(x),
                    z: Box::new(z),
                },
            })
        }

        "or_i" => {
            ctx.next_token(); // Advance past "or_i"
            let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
            let x = parse_internal(ctx)?;
            let (_comma, _comma_column) = ctx.expect_token(",")?;
            let z = parse_internal(ctx)?;
            let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

            Ok(AST {
                position: column,
                fragment: Fragment::OrI {
                    x: Box::new(x),
                    z: Box::new(z),
                },
            })
        }

        "thresh" => {
            ctx.next_token(); // Advance past "thresh"
            let (_l_paren, _l_paren_column) = ctx.expect_token("(")?;
            let (k, k_column) = ctx
                .next_token()
                .ok_or(ParseError::UnexpectedEof { context: "thresh" })?;

            let k = k.parse::<i32>().map_err(|_| ParseError::UnexpectedToken {
                expected: "i32",
                found: (k, k_column),
            })?;

            // Pre-allocate with reasonable capacity to reduce reallocations
            let mut xs = Vec::with_capacity(8);
            while let Some((token, _column)) = ctx.peek_token() {
                if token == ")" {
                    break;
                } else if token == "," {
                    ctx.next_token();
                }
                let x = parse_internal(ctx)?;
                xs.push(Box::new(x));
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
            let mut keys = Vec::with_capacity(8);
            while let Some((token, _column)) = ctx.peek_token() {
                if token == ")" {
                    break;
                } else if token == "," {
                    ctx.next_token();
                }
                let (key, _key_column) = ctx
                    .next_token()
                    .ok_or(ParseError::UnexpectedEof { context: "multi" })?;
                keys.push(key);
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
            let mut keys = Vec::with_capacity(8);
            while let Some((token, _column)) = ctx.peek_token() {
                if token == ")" {
                    break;
                } else if token == "," {
                    ctx.next_token();
                }
                let (key, _key_column) = ctx
                    .next_token()
                    .ok_or(ParseError::UnexpectedEof { context: "multi_a" })?;
                keys.push(key);
            }

            let (_r_paren, _r_paren_column) = ctx.expect_token(")")?;

            Ok(AST {
                position: column,
                fragment: Fragment::MultiA { k, keys },
            })
        }

        _ => {
            // check if is identity

            if let Some((peek_token, _peek_token_column)) = ctx.peek_next_token() {
                if peek_token == ":" {
                    ctx.next_token(); // Advance past identity type

                    ctx.expect_token(":")?;

                    // identity is a list of inner identities, eg av:X

                    let mut node: AST = parse_internal(ctx)?;

                    for id_type in token.chars().rev() {
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
                                    x: Box::new(node),
                                },
                            }
                        } else if id_type == 't' {
                            // t:X = and_v(X,1)
                            node = AST {
                                position: column,
                                fragment: Fragment::AndV {
                                    x: Box::new(node),
                                    y: Box::new(AST {
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
                                    x: Box::new(AST {
                                        position: column,
                                        fragment: Fragment::False,
                                    }),
                                    z: Box::new(node),
                                },
                            }
                        } else if id_type == 'u' {
                            // u:X = or_i(X,0)
                            node = AST {
                                position: column,
                                fragment: Fragment::OrI {
                                    x: Box::new(node),
                                    z: Box::new(AST {
                                        position: column,
                                        fragment: Fragment::False,
                                    }),
                                },
                            }
                        }
                    }

                    return Ok(node);
                }
            }

            Err(ParseError::UnexpectedToken {
                expected: "0 or 1 or pk_k or pk_h or pk or pkh or older or after or sha256 or hash256 or ripemd160 or hash160 or andor or and_v or and_b or and_n or or_b or or_c or or_d or or_i or thresh or multi or multi_a or a:pk_k(key) or v:pk_k(key) or c:pk_k(key) or d:pk_k(key) or s:pk_k(key) or j:pk_k(key) or n:pk_k(key)",
                found: (token, column),
            })
        }
    }
}
