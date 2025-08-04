use f_miniscript::parser::{Context, Fragment, FragmentVisitor};

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

impl<'input> FragmentVisitor<'input> for StringBufferVisitor {
    fn visit_fragment(&mut self, fragment: &Fragment<'input>, ctx: &Context<'input>) {
        match fragment {
            Fragment::False { position } => {
                self.write_line("False");
            }
            Fragment::True { position } => {
                self.write_line("True");
            }
            Fragment::Pk_k { position, key } => {
                self.write_line(&format!("Pk_k({:?})", key));
            }
            Fragment::Pk_h { position, key } => {
                self.write_line(&format!("Pk_h({:?})", key));
            }
            Fragment::Pk { position, key } => {
                self.write_line(&format!("Pk({:?})", key));
            }
            Fragment::Pkh { position, key } => {
                self.write_line(&format!("Pkh({:?})", key));
            }
            Fragment::Older { position, n } => {
                self.write_line(&format!("Older({:?})", n));
            }
            Fragment::After { position, n } => {
                self.write_line(&format!("After({:?})", n));
            }
            Fragment::Sha256 { position, h } => {
                self.write_line(&format!("Sha256({:?})", h));
            }
            Fragment::Hash256 { position, h } => {
                self.write_line(&format!("Hash256({:?})", h));
            }
            Fragment::Ripemd160 { position, h } => {
                self.write_line(&format!("Ripemd160({:?})", h));
            }
            Fragment::Hash160 { position, h } => {
                self.write_line(&format!("Hash160({:?})", h));
            }
            Fragment::AndOr { position, x, y, z } => {
                self.write_line("AndOr(");
                self.indent();

                if let Some(x_fragment) = ctx.get_fragment(*x) {
                    self.visit_fragment(x_fragment, ctx);
                }
                if let Some(y_fragment) = ctx.get_fragment(*y) {
                    self.visit_fragment(y_fragment, ctx);
                }
                if let Some(z_fragment) = ctx.get_fragment(*z) {
                    self.visit_fragment(z_fragment, ctx);
                }

                self.dedent();
                self.write_line(")");
            }
            Fragment::And_v { position, x, y } => {
                self.write_line("And_v(");
                self.indent();
                if let Some(x_fragment) = ctx.get_fragment(*x) {
                    self.visit_fragment(x_fragment, ctx);
                }
                if let Some(y_fragment) = ctx.get_fragment(*y) {
                    self.visit_fragment(y_fragment, ctx);
                }
                self.dedent();
                self.write_line(")");
            }
            Fragment::And_b { position, x, y } => {
                self.write_line("And_b(");
                self.indent();
                if let Some(x_fragment) = ctx.get_fragment(*x) {
                    self.visit_fragment(x_fragment, ctx);
                }
                if let Some(y_fragment) = ctx.get_fragment(*y) {
                    self.visit_fragment(y_fragment, ctx);
                }
                self.dedent();
                self.write_line(")");
            }
            Fragment::And_n { position, x, y } => {
                self.write_line("And_n(");
                self.indent();
                if let Some(x_fragment) = ctx.get_fragment(*x) {
                    self.visit_fragment(x_fragment, ctx);
                }
                if let Some(y_fragment) = ctx.get_fragment(*y) {
                    self.visit_fragment(y_fragment, ctx);
                }
                self.dedent();
                self.write_line(")");
            }
            Fragment::Or_b { position, x, z } => {
                self.write_line("Or_b(");
                self.indent();
                if let Some(x_fragment) = ctx.get_fragment(*x) {
                    self.visit_fragment(x_fragment, ctx);
                }
                if let Some(z_fragment) = ctx.get_fragment(*z) {
                    self.visit_fragment(z_fragment, ctx);
                }
                self.dedent();
                self.write_line(")");
            }
            Fragment::Or_c { position, x, z } => {
                self.write_line("Or_c(");
                self.indent();
                if let Some(x_fragment) = ctx.get_fragment(*x) {
                    self.visit_fragment(x_fragment, ctx);
                }
                if let Some(z_fragment) = ctx.get_fragment(*z) {
                    self.visit_fragment(z_fragment, ctx);
                }
                self.dedent();
                self.write_line(")");
            }
            Fragment::Or_d { position, x, z } => {
                self.write_line("Or_d(");
                self.indent();
                if let Some(x_fragment) = ctx.get_fragment(*x) {
                    self.visit_fragment(x_fragment, ctx);
                }
                if let Some(z_fragment) = ctx.get_fragment(*z) {
                    self.visit_fragment(z_fragment, ctx);
                }
                self.dedent();
                self.write_line(")");
            }
            Fragment::Or_i { position, x, z } => {
                self.write_line("Or_i(");
                self.indent();
                if let Some(x_fragment) = ctx.get_fragment(*x) {
                    self.visit_fragment(x_fragment, ctx);
                }
                if let Some(z_fragment) = ctx.get_fragment(*z) {
                    self.visit_fragment(z_fragment, ctx);
                }
                self.dedent();
                self.write_line(")");
            }
            Fragment::Thresh { position, k, xs } => {
                self.write_line(&format!("Thresh(k={:?}, [", k));
                self.indent();
                for x in xs.iter() {
                    if let Some(x_fragment) = ctx.get_fragment(*x) {
                        self.visit_fragment(x_fragment, ctx);
                    }
                }
                self.dedent();
                self.write_line("])");
            }
            Fragment::Multi { position, k, keys } => {
                self.write_line(&format!("Multi(k={:?}, keys={:?})", k, keys));
            }
            Fragment::Multi_a { position, k, keys } => {
                self.write_line(&format!("Multi_a(k={:?}, keys={:?})", k, keys));
            }
        }
    }
}
