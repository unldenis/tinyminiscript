use core::{
    fmt::{Debug, Display},
    str::Utf8Error,
};

#[derive(Debug, PartialEq)]
pub struct Position {
    pub line: usize,
    pub column: usize,
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

#[derive(Debug)]
pub enum Token<'a> {
    Bool { position: Position, value: bool },
    Int { position: Position, value: u32 },
    Identifier { position: Position, value: &'a str },

    LeftParen(Position),
    RightParen(Position),

    Eq(Position),
    Comma(Position),
    Colon(Position),
    Checksum { position: Position, value: &'a str },

    Eof(Position),
}

impl<'a> Token<'a> {
    pub fn position(&self) -> &Position {
        match self {
            Token::Bool { position, .. } => position,
            Token::Int { position, .. } => position,
            Token::Identifier { position, .. } => position,
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

impl<'a> Display for Token<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Token::Bool { value, .. } => write!(f, "Bool({:?})", value),
            Token::Identifier { value, .. } => write!(f, "Identifier({:?})", value),
            Token::Int { value, .. } => write!(f, "Int({:?})", value),
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

#[derive(Debug)]
pub enum LexerError {
    InvalidNumber {
        position: Position,
    },
    UnknownCharacter {
        position: Position,
        character: char,
    },
    Utf8Error {
        position: Position,
        error: Utf8Error,
    },
}

pub struct Lexer<'a> {
    input: &'a [u8],
    position: usize,
    line: usize,
    column: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a str) -> Self {
        Lexer {
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

    fn read_identifier(&mut self) -> Result<&'a str, LexerError> {
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
        self.input[start..self.position]
            .to_utf8()
            .map_err(|e| LexerError::Utf8Error {
                position: self.get_position(),
                error: e,
            })
    }

    fn read_number(&mut self) -> Result<Option<u32>, LexerError> {
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
            let num_str =
                self.input[start..self.position]
                    .to_utf8()
                    .map_err(|e| LexerError::Utf8Error {
                        position: self.get_position(),
                        error: e,
                    })?;
            Ok(num_str.parse::<u32>().ok())
        } else {
            Ok(None)
        }
    }

    fn read_checksum(&mut self) -> Result<&'a str, LexerError> {
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

        self.input[start..self.position]
            .to_utf8()
            .map_err(|e| LexerError::Utf8Error {
                position: self.get_position(),
                error: e,
            })
    }

    fn get_position(&self) -> Position {
        Position::new(self.line, self.column)
    }

    pub fn next_token(&mut self) -> Result<Token<'a>, LexerError> {
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
                Ok(Token::Bool {
                    position: pos,
                    value: false,
                })
            }
            Some(b'1') => {
                let pos = self.get_position();
                self.advance();
                Ok(Token::Bool {
                    position: pos,
                    value: true,
                })
            }
            Some(b) if b.is_ascii_digit() => {
                let pos = self.get_position();
                match self.read_number()? {
                    Some(num) => Ok(Token::Int {
                        position: pos,
                        value: num,
                    }),
                    None => Err(LexerError::InvalidNumber { position: pos }),
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
                Ok(Token::Identifier {
                    position: pos,
                    value: identifier,
                })
            }
            Some(b) => {
                let pos = self.get_position();
                self.advance(); // Skip unknown character
                Err(LexerError::UnknownCharacter {
                    position: pos,
                    character: char::from(b),
                })
            }
        }
    }
}

impl<'a> Iterator for Lexer<'a> {
    type Item = Result<Token<'a>, LexerError>;

    fn next(&mut self) -> Option<Self::Item> {
        let token_result = self.next_token();
        match token_result {
            Ok(Token::Eof(_)) => None,
            Ok(token) => Some(Ok(token)),
            Err(error) => Some(Err(error)),
        }
    }
}

fn parse_miniscript(script: &str) -> Result<(), LexerError> {
    let lexer = Lexer::new(script);

    // Just iterate through tokens to verify parsing works
    for token_result in lexer {
        let token = token_result?;
        // Process token here if needed
        match token {
            Token::Eof(_) => break,
            _ => continue,
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_miniscript() {
        let script = "and_v(v:pk(K),pk(A))";
        let result = parse_miniscript(script);
        assert!(result.is_ok());
    }

    #[test]
    fn test_simple_identifier() {
        let script = "pk(A)";
        let result = parse_miniscript(script);
        assert!(result.is_ok());
    }

    #[test]
    fn test_with_numbers() {
        let script = "thresh(2,pk(A),pk(B))";
        let result = parse_miniscript(script);
        assert!(result.is_ok());
    }

    #[test]
    fn test_with_colon() {
        let script = "c:pk(A)";
        let result = parse_miniscript(script);
        assert!(result.is_ok());
    }

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
                Token::Identifier { .. }
                | Token::LeftParen(_)
                | Token::RightParen(_)
                | Token::Colon(_)
                | Token::Int { .. }
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
    fn test_position_tracking() {
        let script = "pk(A)\npk(B)";
        let mut lexer = Lexer::new(script);

        // First line tokens
        let token1 = lexer.next_token().unwrap();
        assert_eq!(token1.position(), &Position::new(1, 1)); // "pk"

        let token2 = lexer.next_token().unwrap();
        assert_eq!(token2.position(), &Position::new(1, 3)); // "("

        let token3 = lexer.next_token().unwrap();
        assert_eq!(token3.position(), &Position::new(1, 4)); // "A"

        let token4 = lexer.next_token().unwrap();
        assert_eq!(token4.position(), &Position::new(1, 5)); // ")"

        // Second line tokens
        let token5 = lexer.next_token().unwrap();
        assert_eq!(token5.position(), &Position::new(2, 1)); // "pk"
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
        assert!(matches!(result, Err(LexerError::UnknownCharacter { .. }))); // "@" should error
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
            Token::Identifier { value, .. } => assert_eq!(value, "test"),
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
