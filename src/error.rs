use core::fmt::Debug;

use crate::lexer::Position;

pub struct MiniscriptError<'input, T: Debug> {
    pub input: &'input str,
    pub position: Position,
    pub inner: T,
}

impl<'input, T: Debug> MiniscriptError<'input, T> {
    pub fn new(input: &'input str, position: Position, inner: T) -> Self {
        Self {
            position,
            inner,
            input,
        }
    }
}

impl<'input, T: Debug> Debug for MiniscriptError<'input, T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Get the line where the error occurred
        let lines: core::str::Lines = self.input.lines();
        let error_line = lines
            .enumerate()
            .find(|(line_num, _)| *line_num + 1 == self.position.line)
            .map(|(_, line)| line)
            .unwrap_or("");

        // Calculate the visual column position (accounting for tabs, etc.)
        let visual_column = self.position.column.saturating_sub(1);

        writeln!(f, "error: {:?}", self.inner)?;
        writeln!(
            f,
            "  --> <input>:{}:{}",
            self.position.line, self.position.column
        )?;
        writeln!(f, "   |")?;
        writeln!(f, "{:02} | {}", self.position.line, error_line)?;
        write!(f, "   | ")?;

        // Write spaces for the caret
        for _ in 0..visual_column {
            write!(f, " ")?;
        }
        writeln!(f, "^")?;
        writeln!(f, "   |")
    }
}
