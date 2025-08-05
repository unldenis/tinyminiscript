use core::{
    fmt::{Debug, Display},
    str::Utf8Error,
};

use crate::error::MiniscriptError;

#[derive(Clone, Copy, Default)]
pub struct Position {
    pub line: usize,
    pub column: usize,
}

impl Debug for Position {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}", self.line, self.column)
    }
}

impl Position {
    pub fn new(line: usize, column: usize) -> Self {
        Position { line, column }
    }
}

pub trait ToUtf8 {
    fn to_utf8(&self) -> Result<&str, Utf8Error>;
}

impl ToUtf8 for [u8] {
    fn to_utf8(&self) -> Result<&str, Utf8Error> {
        core::str::from_utf8(self)
    }
}

pub enum Token<'input> {
    Bool {
        position: Position,
        value: bool,
    },
    Int(Int),
    Identifier(Identifier<'input>),

    LeftParen(Position),
    RightParen(Position),

    Eq(Position),
    Comma(Position),
    Colon(Position),
    Checksum {
        position: Position,
        value: &'input str,
    },

    Eof(Position),
}

impl<'input> Debug for Token<'input> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Token::Bool { value, .. } => write!(f, "Bool({})", value),
            Token::Identifier(id) => write!(f, "{:?}", id),
            Token::Int(int) => write!(f, "{:?}", int),
            Token::LeftParen(_) => write!(f, "LeftParen"),
            Token::RightParen(_) => write!(f, "RightParen"),
            Token::Eq(_) => write!(f, "Eq"),
            Token::Comma(_) => write!(f, "Comma"),
            Token::Colon(_) => write!(f, "Colon"),
            Token::Checksum { value, .. } => write!(f, "Checksum({:?})", value),
            Token::Eof(_) => write!(f, "Eof"),
        }
    }
}

pub struct Int {
    pub position: Position,
    pub value: u32,
}

impl Debug for Int {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Int({})", self.value)
    }
}

pub struct Identifier<'input> {
    pub position: Position,
    pub value: &'input str,
}

impl<'input> Debug for Identifier<'input> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Identifier({:?})", self.value)
    }
}

impl<'input> Token<'input> {
    pub fn position(&self) -> &Position {
        match self {
            Token::Bool { position, .. } => position,
            Token::Int(Int { position, .. }) => position,
            Token::Identifier(Identifier { position, .. }) => position,
            Token::LeftParen(position) => position,
            Token::RightParen(position) => position,
            Token::Eq(position) => position,
            Token::Comma(position) => position,
            Token::Colon(position) => position,
            Token::Checksum { position, .. } => position,
            Token::Eof(position) => position,
        }
    }
}

impl<'input> Display for Token<'input> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Token::Bool { value, .. } => write!(f, "Bool({:?})", value),
            Token::Identifier(Identifier { value, .. }) => write!(f, "Identifier({:?})", value),
            Token::Int(Int { value, .. }) => write!(f, "Int({:?})", value),
            Token::LeftParen(_) => write!(f, "LeftParen"),
            Token::RightParen(_) => write!(f, "RightParen"),
            Token::Eq(_) => write!(f, "Eq"),
            Token::Comma(_) => write!(f, "Comma"),
            Token::Colon(_) => write!(f, "Colon"),
            Token::Checksum { value, .. } => write!(f, "Checksum({:?})", value),
            Token::Eof(_) => write!(f, "Eof"),
        }
    }
}

pub enum LexerError {
    InvalidNumber,
    UnknownCharacter { character: char },
    Utf8Error { error: Utf8Error },
}

impl Debug for LexerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            LexerError::InvalidNumber => write!(f, "Invalid number"),
            LexerError::UnknownCharacter { character } => {
                write!(f, "Unknown character: {}", character)
            }
            LexerError::Utf8Error { error } => write!(f, "UTF-8 error: {}", error),
        }
    }
}

pub struct Lexer<'input> {
    pub(crate) _input: &'input str,
    input: &'input [u8],
    position: usize,
    line: usize,
    column: usize,
}

impl<'input> Lexer<'input> {
    pub fn new(input: &'input str) -> Self {
        Lexer {
            _input: input,
            input: input.as_bytes(),
            position: 0,
            line: 1,
            column: 1,
        }
    }

    fn peek(&self) -> Option<u8> {
        if self.position < self.input.len() {
            Some(self.input[self.position])
        } else {
            None
        }
    }

    fn advance(&mut self) {
        if self.position < self.input.len() {
            let byte = self.input[self.position];
            if byte == b'\n' {
                self.line += 1;
                self.column = 1;
            } else {
                self.column += 1;
            }
            self.position += 1;
        }
    }

    fn skip_whitespace(&mut self) {
        while let Some(b) = self.peek() {
            if b.is_ascii_whitespace() {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn read_identifier(&mut self) -> Result<&'input str, MiniscriptError<'input, LexerError>> {
        let start = self.position;
        while let Some(b) = self.peek() {
            if b.is_ascii_alphanumeric()
                || b == b'_'
                || b == b'['
                || b == b']'
                || b == b'\''
                || b == b'*'
                || b == b'/'
            {
                self.advance();
            } else {
                break;
            }
        }
        self.input[start..self.position].to_utf8().map_err(|e| {
            MiniscriptError::new(
                self._input,
                self.get_position(),
                LexerError::Utf8Error { error: e },
            )
        })
    }

    fn read_number(&mut self) -> Result<Option<u32>, MiniscriptError<'input, LexerError>> {
        let start = self.position;
        let mut has_digits = false;

        while let Some(b) = self.peek() {
            if b.is_ascii_digit() {
                has_digits = true;
                self.advance();
            } else {
                break;
            }
        }

        if has_digits {
            let num_str = self.input[start..self.position].to_utf8().map_err(|e| {
                MiniscriptError::new(
                    self._input,
                    self.get_position(),
                    LexerError::Utf8Error { error: e },
                )
            })?;
            Ok(num_str.parse::<u32>().ok())
        } else {
            Ok(None)
        }
    }

    fn read_checksum(&mut self) -> Result<&'input str, MiniscriptError<'input, LexerError>> {
        // Skip the '#' character
        self.advance();

        let start = self.position;

        // Read alphanumeric characters for the checksum
        while let Some(b) = self.peek() {
            if b.is_ascii_alphanumeric() {
                self.advance();
            } else {
                break;
            }
        }

        self.input[start..self.position].to_utf8().map_err(|e| {
            MiniscriptError::new(
                self._input,
                self.get_position(),
                LexerError::Utf8Error { error: e },
            )
        })
    }

    fn get_position(&self) -> Position {
        Position::new(self.line, self.column)
    }

    pub fn next_token(&mut self) -> Result<Token<'input>, MiniscriptError<'input, LexerError>> {
        self.skip_whitespace();

        match self.peek() {
            None => Ok(Token::Eof(self.get_position())),
            Some(b'(') => {
                let pos = self.get_position();
                self.advance();
                Ok(Token::LeftParen(pos))
            }
            Some(b')') => {
                let pos = self.get_position();
                self.advance();
                Ok(Token::RightParen(pos))
            }
            Some(b'=') => {
                let pos = self.get_position();
                self.advance();
                Ok(Token::Eq(pos))
            }
            Some(b',') => {
                let pos = self.get_position();
                self.advance();
                Ok(Token::Comma(pos))
            }
            Some(b':') => {
                let pos = self.get_position();
                self.advance();
                Ok(Token::Colon(pos))
            }
            Some(b'#') => {
                let pos = self.get_position();
                let checksum = self.read_checksum()?;
                Ok(Token::Checksum {
                    position: pos,
                    value: checksum,
                })
            }
            Some(b'0') => {
                let pos = self.get_position();
                self.advance();
                // Check if there are more digits after '0'
                if let Some(b) = self.peek() {
                    if b.is_ascii_digit() {
                        // This is part of a larger number, rewind and parse as number
                        self.position = pos.column - 1; // Rewind to start of number
                        match self.read_number()? {
                            Some(num) => Ok(Token::Int(Int {
                                position: pos,
                                value: num,
                            })),
                            None => Err(MiniscriptError::new(
                                self._input,
                                pos,
                                LexerError::InvalidNumber,
                            )),
                        }
                    } else {
                        // Standalone '0', treat as boolean false
                        Ok(Token::Bool {
                            position: pos,
                            value: false,
                        })
                    }
                } else {
                    // End of input, treat as boolean false
                    Ok(Token::Bool {
                        position: pos,
                        value: false,
                    })
                }
            }
            Some(b'1') => {
                let pos = self.get_position();
                self.advance();
                // Check if there are more digits after '1'
                if let Some(b) = self.peek() {
                    if b.is_ascii_digit() {
                        // This is part of a larger number, rewind and parse as number
                        self.position = pos.column - 1; // Rewind to start of number
                        match self.read_number()? {
                            Some(num) => Ok(Token::Int(Int {
                                position: pos,
                                value: num,
                            })),
                            None => Err(MiniscriptError::new(
                                self._input,
                                pos,
                                LexerError::InvalidNumber,
                            )),
                        }
                    } else {
                        // Standalone '1', treat as boolean true
                        Ok(Token::Bool {
                            position: pos,
                            value: true,
                        })
                    }
                } else {
                    // End of input, treat as boolean true
                    Ok(Token::Bool {
                        position: pos,
                        value: true,
                    })
                }
            }

            Some(b) if b.is_ascii_digit() && b != b'0' && b != b'1' => {
                let pos = self.get_position();
                match self.read_number()? {
                    Some(num) => Ok(Token::Int(Int {
                        position: pos,
                        value: num,
                    })),
                    None => Err(MiniscriptError::new(
                        self._input,
                        pos,
                        LexerError::InvalidNumber,
                    )),
                }
            }
            Some(b)
                if b.is_ascii_alphabetic()
                    || b == b'_'
                    || b == b'['
                    || b == b']'
                    || b == b'\''
                    || b == b'*'
                    || b == b'/' =>
            {
                let pos = self.get_position();
                let identifier = self.read_identifier()?;
                Ok(Token::Identifier(Identifier {
                    position: pos,
                    value: identifier,
                }))
            }
            Some(b) => {
                let pos = self.get_position();
                self.advance(); // Skip unknown character
                Err(MiniscriptError::new(
                    self._input,
                    pos,
                    LexerError::UnknownCharacter {
                        character: char::from(b),
                    },
                ))
            }
        }
    }
}

impl<'input> Iterator for Lexer<'input> {
    type Item = Result<Token<'input>, MiniscriptError<'input, LexerError>>;

    fn next(&mut self) -> Option<Self::Item> {
        let token_result = self.next_token();
        match token_result {
            Ok(Token::Eof(_)) => None,
            Ok(token) => Some(Ok(token)),
            Err(error) => Some(Err(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_iteration() {
        let script = "and_v(v:pk(K),pk(A))";
        let lexer = Lexer::new(script);

        let mut token_count = 0;
        for token_result in lexer {
            let token = token_result.unwrap();
            token_count += 1;
            // Verify token types - accept all valid token types
            match token {
                Token::Identifier(Identifier { .. })
                | Token::LeftParen(_)
                | Token::RightParen(_)
                | Token::Colon(_)
                | Token::Int(Int { .. })
                | Token::Comma(_) => {}
                Token::Eof(_) => break,
                _ => panic!("Unexpected token type: {}", token),
            }
        }
        // The script "and_v(v:pk(K),pk(A))" should produce:
        // and_v, (, v, :, pk, (, K, ), ,, pk, (, A, ), )
        // That's 14 tokens total
        assert_eq!(token_count, 14);
    }

    #[test]
    fn test_error_handling() {
        // Test with a simpler error case - invalid character
        let script = "pk(A@)"; // @ is not a valid character for identifiers
        let mut lexer = Lexer::new(script);

        // Should handle errors gracefully
        let result = lexer.next_token();
        assert!(result.is_ok()); // "pk" should parse fine

        let result = lexer.next_token();
        assert!(result.is_ok()); // "(" should parse fine

        let result = lexer.next_token();
        assert!(result.is_ok()); // "A" should parse fine

        let result = lexer.next_token();
        assert!(matches!(
            result,
            Err(MiniscriptError {
                inner: LexerError::UnknownCharacter { .. },
                ..
            })
        )); // "@" should error
    }

    #[test]
    fn test_boolean_literals() {
        let script = "0 1";
        let mut lexer = Lexer::new(script);

        // Test false literal
        let token1 = lexer.next_token().unwrap();
        match token1 {
            Token::Bool { value, .. } => assert_eq!(value, false),
            _ => panic!("Expected Bool(false), got {:?}", token1),
        }

        // Test true literal
        let token2 = lexer.next_token().unwrap();
        match token2 {
            Token::Bool { value, .. } => assert_eq!(value, true),
            _ => panic!("Expected Bool(true), got {:?}", token2),
        }

        // Test EOF
        let token3 = lexer.next_token().unwrap();
        assert!(matches!(token3, Token::Eof(_)));
    }

    #[test]
    fn test_checksum_parsing() {
        let script = "pkh([d6043800/0'/0'/18']03efdee34c0009fd175f3b20b5e5a5517fd5d16746f2e635b44617adafeaebc388)#4ahsl9pk";
        let lexer = Lexer::new(script);

        // Skip through the tokens until we find the checksum
        let mut found_checksum = false;
        for token_result in lexer {
            let token = token_result.unwrap();
            match token {
                Token::Checksum { value, .. } => {
                    assert_eq!(value, "4ahsl9pk");
                    found_checksum = true;
                    break;
                }
                Token::Eof(_) => break,
                _ => continue,
            }
        }
        assert!(found_checksum, "Checksum token not found");
    }

    #[test]
    fn test_simple_checksum() {
        let script = "test#abc123";
        let mut lexer = Lexer::new(script);

        // Get the identifier
        let token1 = lexer.next_token().unwrap();
        match token1 {
            Token::Identifier(Identifier { value, .. }) => assert_eq!(value, "test"),
            _ => panic!("Expected Identifier, got {:?}", token1),
        }

        // Get the checksum
        let token2 = lexer.next_token().unwrap();
        match token2 {
            Token::Checksum { value, .. } => assert_eq!(value, "abc123"),
            _ => panic!("Expected Checksum, got {:?}", token2),
        }

        // Test EOF
        let token3 = lexer.next_token().unwrap();
        assert!(matches!(token3, Token::Eof(_)));
    }
}
