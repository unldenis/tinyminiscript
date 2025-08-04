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
            Fragment::False { position: _ } => {
                self.write_line("False");
            }
            Fragment::True { position: _ } => {
                self.write_line("True");
            }
            Fragment::PkK { position: _, key } => {
                self.write_line(&format!("PkK({:?})", key));
            }
            Fragment::PkH { position: _, key } => {
                self.write_line(&format!("PkH({:?})", key));
            }
            Fragment::Pk { position: _, key } => {
                self.write_line(&format!("Pk({:?})", key));
            }
            Fragment::Pkh { position: _, key } => {
                self.write_line(&format!("Pkh({:?})", key));
            }
            Fragment::Older { position: _, n } => {
                self.write_line(&format!("Older({:?})", n));
            }
            Fragment::After { position: _, n } => {
                self.write_line(&format!("After({:?})", n));
            }
            Fragment::Sha256 { position: _, h } => {
                self.write_line(&format!("Sha256({:?})", h));
            }
            Fragment::Hash256 { position: _, h } => {
                self.write_line(&format!("Hash256({:?})", h));
            }
            Fragment::Ripemd160 { position: _, h } => {
                self.write_line(&format!("Ripemd160({:?})", h));
            }
            Fragment::Hash160 { position: _, h } => {
                self.write_line(&format!("Hash160({:?})", h));
            }
            Fragment::AndOr {
                position: _,
                x,
                y,
                z,
            } => {
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
            Fragment::AndV { position: _, x, y } => {
                self.write_line("AndV(");
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
            Fragment::AndB { position: _, x, y } => {
                self.write_line("AndB(");
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
            Fragment::AndN { position: _, x, y } => {
                self.write_line("AndN(");
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
            Fragment::OrB { position: _, x, z } => {
                self.write_line("OrB(");
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
            Fragment::OrC { position: _, x, z } => {
                self.write_line("OrC(");
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
            Fragment::OrD { position: _, x, z } => {
                self.write_line("OrD(");
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
            Fragment::OrI { position: _, x, z } => {
                self.write_line("OrI(");
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
            Fragment::Thresh { position: _, k, xs } => {
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
            Fragment::Multi {
                position: _,
                k,
                keys,
            } => {
                self.write_line(&format!("Multi(k={:?}, keys={:?})", k, keys));
            }
            Fragment::MultiA {
                position: _,
                k,
                keys,
            } => {
                self.write_line(&format!("MultiA(k={:?}, keys={:?})", k, keys));
            }
        }
    }
}
