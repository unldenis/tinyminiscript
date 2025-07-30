use core::fmt::Debug;


#[derive(Debug)]
pub enum Token<'a> {
    Bool(bool),
    Int(u32),
    Identifier(&'a [u8]),

    LeftParen,
    RightParen,
    
    Eq,
    Comma,
    Colon,
    
    Eof,
}


#[derive(Debug)]
pub enum LexerError {
    InvalidNumber,
    UnknownCharacter(u8),
}

pub struct Lexer<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Lexer<'a> {
    pub fn new(input: &'a str) -> Self {
        Lexer {
            input: input.as_bytes(),
            position: 0,
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

    fn read_identifier(&mut self) -> &'a [u8] {
        let start = self.position;
        while let Some(b) = self.peek() {
            if b.is_ascii_alphanumeric() || b == b'_' || b == b'[' || b == b']' || b == b'\'' || b == b'*' || b == b'/' {
                self.advance();
            } else {
                break;
            }
        }
        &self.input[start..self.position]
    }

    fn read_number(&mut self) -> Option<u32> {
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
            let num_str = core::str::from_utf8(&self.input[start..self.position]).ok()?;
            num_str.parse::<u32>().ok()
        } else {
            None
        }
    }

    pub fn next_token(&mut self) -> Result<Token<'a>, LexerError> {
        self.skip_whitespace();
        
        match self.peek() {
            None => Ok(Token::Eof),
            Some(b'(') => {
                self.advance();
                Ok(Token::LeftParen)
            }
            Some(b')') => {
                self.advance();
                Ok(Token::RightParen)
            }
            Some(b'=') => {
                self.advance();
                Ok(Token::Eq)
            }
            Some(b',') => {
                self.advance();
                Ok(Token::Comma)
            }
            Some(b':') => {
                self.advance();
                Ok(Token::Colon)
            }
            Some(b) if b.is_ascii_digit() => {
                if let Some(num) = self.read_number() {
                    Ok(Token::Int(num))
                } else {
                    Err(LexerError::InvalidNumber)
                }
            }
            Some(b) if b.is_ascii_alphabetic() || b == b'_' || b == b'[' || b == b']' || b == b'\'' || b == b'*' || b == b'/' => {
                let identifier = self.read_identifier();
                Ok(Token::Identifier(identifier))
            }
            Some(b) => {
                self.advance(); // Skip unknown character
                Err(LexerError::UnknownCharacter(b))
            }
        }
    }
}

impl<'a> Iterator for Lexer<'a> {
    type Item = Result<Token<'a>, LexerError>;

    fn next(&mut self) -> Option<Self::Item> {
        let token_result = self.next_token();
        match token_result {
            Ok(Token::Eof) => None,
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
            Token::Eof => break,
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
                Token::Identifier(_) | Token::LeftParen | Token::RightParen | 
                Token::Colon | Token::Int(_) | Token::Comma => {},
                Token::Eof => break,
                _ => panic!("Unexpected token type: {:?}", token),
            }
        }
        // The script "and_v(v:pk(K),pk(A))" should produce:
        // and_v, (, v, :, pk, (, K, ), ,, pk, (, A, ), )
        // That's 14 tokens total
        assert_eq!(token_count, 14);
    }
}