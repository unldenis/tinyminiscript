use core::{fmt::Debug, marker::PhantomData};

use heapless::Vec;

use crate::lexer::{Identifier, Int, Lexer, LexerError, Position, Token};

#[derive(Debug)]
pub enum Fragment<'input> {
    // Basic Fragments
    /// 0
    False { position: Position },
    /// 1
    True { position: Position },

    // Key Fragments
    /// pk_k(key)
    Pk_k {
        position: Position,
        key: Token<'input>,
    },
    /// pk_h(key)
    Pk_h {
        position: Position,
        key: Token<'input>,
    },
    /// pk(key) = c:pk_k(key)
    Pk {
        position: Position,
        key: Token<'input>,
    },
    /// pkh(key) = c:pk_h(key)
    Pkh {
        position: Position,
        key: Token<'input>,
    },

    // Time fragments
    /// older(n)
    Older { position: &'input Position, n: Int },
    /// after(n)
    After { position: &'input Position, n: Int },

    // Logical Fragments
    /// andor(X,Y,Z)
    AndOr {
        position: &'input Position,
        x: &'input Fragment<'input>,
        y: &'input Fragment<'input>,
        z: &'input Fragment<'input>,
    },
    /// and_v(X,Y)
    And_v {
        position: &'input Position,
        x: &'input Fragment<'input>,
        y: &'input Fragment<'input>,
    },
    /// and_b(X,Y)
    And_b {
        position: &'input Position,
        x: &'input Fragment<'input>,
        y: &'input Fragment<'input>,
    },
    /// and_n(X,Y) = andor(X,Y,0)
    And_n {
        position: &'input Position,
        x: &'input Fragment<'input>,
        y: &'input Fragment<'input>,
    },
    /// or_b(X,Z)
    Or_b {
        position: &'input Position,
        x: &'input Fragment<'input>,
        z: &'input Fragment<'input>,
    },
    /// or_c(X,Z)
    Or_c {
        position: &'input Position,
        x: &'input Fragment<'input>,
        z: &'input Fragment<'input>,
    },
    /// or_d(X,Z)
    Or_d {
        position: &'input Position,
        x: &'input Fragment<'input>,
        z: &'input Fragment<'input>,
    },
    /// or_i(X,Z)
    Or_i {
        position: &'input Position,
        x: &'input Fragment<'input>,
        z: &'input Fragment<'input>,
    },

    // Threshold Fragments
    /// thresh(k,X1,...,Xn)
    Thresh {
        position: &'input Position,
        k: Int,
        xs: Vec<&'input Fragment<'input>, 16>,
    },
    ///  multi(k,key1,...,keyn)
    /// (P2WSH only)
    Multi {
        position: &'input Position,
        k: Int,
        keys: Vec<&'input Identifier<'input>, 16>,
    },
    /// multi_a(k,key1,...,keyn)
    /// (Tapscript only)
    Multi_a {
        position: &'input Position,
        k: Int,
        keys: Vec<&'input Identifier<'input>, 16>,
    },
}

#[derive(Debug)]
pub enum ParserError<'input> {
    LexerError(LexerError),
    UnexpectedEof(Position),
    UnexpectedToken {
        expected: &'static str,
        found: Token<'input>,
    },
}

pub struct Parser<'input> {
    phantom: PhantomData<&'input ()>,
}

impl<'input> Parser<'input> {
    pub fn new() -> Self {
        Self {
            phantom: PhantomData,
        }
    }

    pub fn parse(
        &'input self,
        lexer: &mut Lexer<'input>,
    ) -> Result<Fragment<'input>, ParserError<'input>> {
        self.parse_key_fragment(lexer)
    }

    fn parse_key_fragment(
        &'input self,
        lexer: &mut Lexer<'input>,
    ) -> Result<Fragment<'input>, ParserError<'input>> {
        let next_token = self.next_token(lexer)?;
        match &next_token {
            Token::Identifier(identifier) => match identifier.value {
                "pk_k" => {
                    self.expect_token(lexer, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                    let key_token = self
                        .expect_token(lexer, "Identifier", |t| matches!(t, Token::Identifier(_)))?;

                    self.expect_token(lexer, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                    return Ok(Fragment::Pk_k {
                        position: identifier.position.clone(),
                        key: key_token,
                    });
                }
                "pk_h" => {
                    self.expect_token(lexer, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                    let key_token = self
                        .expect_token(lexer, "Identifier", |t| matches!(t, Token::Identifier(_)))?;

                    self.expect_token(lexer, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                    return Ok(Fragment::Pk_h {
                        position: identifier.position.clone(),
                        key: key_token,
                    });
                }
                "pk" => {
                    self.expect_token(lexer, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                    let key_token = self
                        .expect_token(lexer, "Identifier", |t| matches!(t, Token::Identifier(_)))?;

                    self.expect_token(lexer, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                    return Ok(Fragment::Pk {
                        position: identifier.position.clone(),
                        key: key_token,
                    });
                }
                "pkh" => {
                    self.expect_token(lexer, "LeftParen", |t| matches!(t, Token::LeftParen(_)))?;

                    let key_token = self
                        .expect_token(lexer, "Identifier", |t| matches!(t, Token::Identifier(_)))?;

                    self.expect_token(lexer, "RightParen", |t| matches!(t, Token::RightParen(_)))?;

                    return Ok(Fragment::Pkh {
                        position: identifier.position.clone(),
                        key: key_token,
                    });
                }
                _ => {}
            },
            _ => {}
        }
        self.parse_basic_fragment(next_token)
    }

    fn parse_basic_fragment(
        &'input self,
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

    fn next_token(&self, lexer: &mut Lexer<'input>) -> Result<Token<'input>, ParserError> {
        let token_result = lexer.next_token();
        match token_result {
            Ok(Token::Eof(position)) => Err(ParserError::UnexpectedEof(position)),
            Ok(token) => Ok(token),
            Err(error) => Err(ParserError::LexerError(error))?,
        }
    }

    fn expect_token(
        &'input self,
        lexer: &mut Lexer<'input>,
        expected: &'static str,
        token_matcher: impl Fn(&Token<'input>) -> bool,
    ) -> Result<Token<'input>, ParserError<'input>> {
        let token = self.next_token(lexer)?;
        if token_matcher(&token) {
            Ok(token)
        } else {
            Err(ParserError::UnexpectedToken {
                expected,
                found: token,
            })
        }
    }
}
