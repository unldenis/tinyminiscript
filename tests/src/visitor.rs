use f_miniscript::{
    parser::{Context, Fragment, Node},
    visitor::NodeVisitor,
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

impl<'input> NodeVisitor<'input> for StringBufferVisitor {
    fn visit_node(&mut self, node: &Node<'input>, ctx: &Context<'input>) {
        match &node.fragment {
            Fragment::False => {
                self.write_line("False");
            }
            Fragment::True => {
                self.write_line("True");
            }
            Fragment::PkK { key } => {
                self.write_line(&format!("PkK({:?})", key));
            }
            Fragment::PkH { key } => {
                self.write_line(&format!("PkH({:?})", key));
            }
            Fragment::Pk { key } => {
                self.write_line(&format!("Pk({:?})", key));
            }
            Fragment::Pkh { key } => {
                self.write_line(&format!("Pkh({:?})", key));
            }
            Fragment::Older { n } => {
                self.write_line(&format!("Older({:?})", n));
            }
            Fragment::After { n } => {
                self.write_line(&format!("After({:?})", n));
            }
            Fragment::Sha256 { h } => {
                self.write_line(&format!("Sha256({:?})", h));
            }
            Fragment::Hash256 { h } => {
                self.write_line(&format!("Hash256({:?})", h));
            }
            Fragment::Ripemd160 { h } => {
                self.write_line(&format!("Ripemd160({:?})", h));
            }
            Fragment::Hash160 { h } => {
                self.write_line(&format!("Hash160({:?})", h));
            }
            Fragment::AndOr { x, y, z } => {
                self.write_line("AndOr(");
                self.indent();

                if let Some(x_node) = ctx.get_node(*x) {
                    self.visit_node(x_node, ctx);
                }
                if let Some(y_node) = ctx.get_node(*y) {
                    self.visit_node(y_node, ctx);
                }
                if let Some(z_node) = ctx.get_node(*z) {
                    self.visit_node(z_node, ctx);
                }

                self.dedent();
                self.write_line(")");
            }
            Fragment::AndV { x, y } => {
                self.write_line("AndV(");
                self.indent();
                if let Some(x_node) = ctx.get_node(*x) {
                    self.visit_node(x_node, ctx);
                }
                if let Some(y_node) = ctx.get_node(*y) {
                    self.visit_node(y_node, ctx);
                }
                self.dedent();
                self.write_line(")");
            }
            Fragment::AndB { x, y } => {
                self.write_line("AndB(");
                self.indent();
                if let Some(x_node) = ctx.get_node(*x) {
                    self.visit_node(x_node, ctx);
                }
                if let Some(y_node) = ctx.get_node(*y) {
                    self.visit_node(y_node, ctx);
                }
                self.dedent();
                self.write_line(")");
            }
            Fragment::AndN { x, y } => {
                self.write_line("AndN(");
                self.indent();
                if let Some(x_node) = ctx.get_node(*x) {
                    self.visit_node(x_node, ctx);
                }
                if let Some(y_node) = ctx.get_node(*y) {
                    self.visit_node(y_node, ctx);
                }
                self.dedent();
                self.write_line(")");
            }
            Fragment::OrB { x, z } => {
                self.write_line("OrB(");
                self.indent();
                if let Some(x_node) = ctx.get_node(*x) {
                    self.visit_node(x_node, ctx);
                }
                if let Some(z_node) = ctx.get_node(*z) {
                    self.visit_node(z_node, ctx);
                }
                self.dedent();
                self.write_line(")");
            }
            Fragment::OrC { x, z } => {
                self.write_line("OrC(");
                self.indent();
                if let Some(x_node) = ctx.get_node(*x) {
                    self.visit_node(x_node, ctx);
                }
                if let Some(z_node) = ctx.get_node(*z) {
                    self.visit_node(z_node, ctx);
                }
                self.dedent();
                self.write_line(")");
            }
            Fragment::OrD { x, z } => {
                self.write_line("OrD(");
                self.indent();
                if let Some(x_node) = ctx.get_node(*x) {
                    self.visit_node(x_node, ctx);
                }
                if let Some(z_node) = ctx.get_node(*z) {
                    self.visit_node(z_node, ctx);
                }
                self.dedent();
                self.write_line(")");
            }
            Fragment::OrI { x, z } => {
                self.write_line("OrI(");
                self.indent();
                if let Some(x_node) = ctx.get_node(*x) {
                    self.visit_node(x_node, ctx);
                }
                if let Some(z_node) = ctx.get_node(*z) {
                    self.visit_node(z_node, ctx);
                }
                self.dedent();
                self.write_line(")");
            }
            Fragment::Thresh { k, xs } => {
                self.write_line(&format!("Thresh(k={:?}, [", k));
                self.indent();
                for x in xs.iter() {
                    if let Some(x_node) = ctx.get_node(*x) {
                        self.visit_node(x_node, ctx);
                    }
                }
                self.dedent();
                self.write_line("])");
            }
            Fragment::Multi { k, keys } => {
                self.write_line(&format!("Multi(k={:?}, keys={:?})", k, keys));
            }
            Fragment::MultiA { k, keys } => {
                self.write_line(&format!("MultiA(k={:?}, keys={:?})", k, keys));
            }
        }
    }
}
