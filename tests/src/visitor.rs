use f_miniscript::{
    parser::{Context, Fragment, Node},
    visitor::{CorrectnessPropertiesVisitorError, NodeVisitor},
};

pub struct StringBufferVisitor {
    buffer: String,
    indent_level: usize,
}

impl StringBufferVisitor {
    pub fn new() -> Self {
        Self {
            buffer: String::new(),
            indent_level: 0,
        }
    }

    pub fn get_result(self) -> String {
        self.buffer
    }

    fn indent(&mut self) {
        self.indent_level += 1;
    }

    fn dedent(&mut self) {
        if self.indent_level > 0 {
            self.indent_level -= 1;
        }
    }

    fn write_indent(&mut self) {
        for _ in 0..self.indent_level {
            self.buffer.push_str("  ");
        }
    }

    fn write_line(&mut self, content: &str) {
        self.write_indent();
        self.buffer.push_str(content);
        self.buffer.push('\n');
    }
}

#[derive(Debug)]
pub enum StringBufferVisitorError {}

impl<'input> NodeVisitor<'input, 256, ()> for StringBufferVisitor {
    type Error = StringBufferVisitorError;

    fn visit_node(
        &mut self,
        node: &Node<'input>,
        ctx: &Context<'input>,
    ) -> Result<(), Self::Error> {
        match &node.fragment {
            Fragment::False => {
                self.write_line("False");
                Ok(())
            }
            Fragment::True => {
                self.write_line("True");
                Ok(())
            }
            Fragment::PkK { key } => {
                self.write_line(&format!("PkK({:?})", key));
                Ok(())
            }
            Fragment::PkH { key } => {
                self.write_line(&format!("PkH({:?})", key));
                Ok(())
            }
            Fragment::Pk { key } => {
                self.write_line(&format!("Pk({:?})", key));
                Ok(())
            }
            Fragment::Pkh { key } => {
                self.write_line(&format!("Pkh({:?})", key));
                Ok(())
            }
            Fragment::Older { n } => {
                self.write_line(&format!("Older({:?})", n));
                Ok(())
            }
            Fragment::After { n } => {
                self.write_line(&format!("After({:?})", n));
                Ok(())
            }
            Fragment::Sha256 { h } => {
                self.write_line(&format!("Sha256({:?})", h));
                Ok(())
            }
            Fragment::Hash256 { h } => {
                self.write_line(&format!("Hash256({:?})", h));
                Ok(())
            }
            Fragment::Ripemd160 { h } => {
                self.write_line(&format!("Ripemd160({:?})", h));
                Ok(())
            }
            Fragment::Hash160 { h } => {
                self.write_line(&format!("Hash160({:?})", h));
                Ok(())
            }
            Fragment::AndOr { x, y, z } => {
                self.write_line("AndOr(");
                self.indent();

                self.visit_node_by_idx(*x, ctx)?;
                self.visit_node_by_idx(*y, ctx)?;
                self.visit_node_by_idx(*z, ctx)?;

                self.dedent();
                self.write_line(")");
                Ok(())
            }
            Fragment::AndV { x, y } => {
                self.write_line("AndV(");
                self.indent();
                self.visit_node_by_idx(*x, ctx)?;
                self.visit_node_by_idx(*y, ctx)?;
                self.dedent();
                self.write_line(")");
                Ok(())
            }
            Fragment::AndB { x, y } => {
                self.write_line("AndB(");
                self.indent();
                self.visit_node_by_idx(*x, ctx)?;
                self.visit_node_by_idx(*y, ctx)?;
                self.dedent();
                self.write_line(")");
                Ok(())
            }
            Fragment::AndN { x, y } => {
                self.write_line("AndN(");
                self.indent();
                self.visit_node_by_idx(*x, ctx)?;
                self.visit_node_by_idx(*y, ctx)?;
                self.dedent();
                self.write_line(")");
                Ok(())
            }
            Fragment::OrB { x, z } => {
                self.write_line("OrB(");
                self.indent();
                self.visit_node_by_idx(*x, ctx)?;
                self.visit_node_by_idx(*z, ctx)?;
                self.dedent();
                self.write_line(")");
                Ok(())
            }
            Fragment::OrC { x, z } => {
                self.write_line("OrC(");
                self.indent();
                self.visit_node_by_idx(*x, ctx)?;
                self.visit_node_by_idx(*z, ctx)?;
                self.dedent();
                self.write_line(")");
                Ok(())
            }
            Fragment::OrD { x, z } => {
                self.write_line("OrD(");
                self.indent();
                self.visit_node_by_idx(*x, ctx)?;
                self.visit_node_by_idx(*z, ctx)?;
                self.dedent();
                self.write_line(")");
                Ok(())
            }
            Fragment::OrI { x, z } => {
                self.write_line("OrI(");
                self.indent();
                self.visit_node_by_idx(*x, ctx)?;
                self.visit_node_by_idx(*z, ctx)?;
                self.dedent();
                self.write_line(")");
                Ok(())
            }
            Fragment::Thresh { k, xs } => {
                self.write_line(&format!("Thresh(k={:?}, [", k));
                self.indent();
                for x in xs.iter() {
                    self.visit_node_by_idx(*x, ctx)?;
                }
                self.dedent();
                self.write_line("])");
                Ok(())
            }
            Fragment::Multi { k, keys } => {
                self.write_line(&format!("Multi(k={:?}, keys={:?})", k, keys));
                Ok(())
            }
            Fragment::MultiA { k, keys } => {
                self.write_line(&format!("MultiA(k={:?}, keys={:?})", k, keys));
                Ok(())
            }
            Fragment::Identity { identity_type, x } => {
                self.write_line(&format!("Identity-{:?}(", identity_type));
                self.indent();
                let x = self.visit_node_by_idx(*x, ctx)?;
                self.dedent();
                self.write_line(")");
                Ok(())
            }
        }
    }
}
