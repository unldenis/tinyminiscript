// AST Printer

use miniscript_rs::parser::{AST, Fragment, ParserContext};

pub struct ASTPrinter {
    indent_level: usize,
    output: String,
}

impl ASTPrinter {
    pub fn new() -> Self {
        Self {
            indent_level: 0,
            output: String::new(),
        }
    }

    pub fn print_ast(&mut self, ctx: &ParserContext) -> String {
        self.output.clear();
        self.print_node(ctx, ctx.get_root());
        self.output.clone()
    }

    fn print_node(&mut self, ctx: &ParserContext, ast: &AST) {
        self.write_indent();
        match &ast.fragment {
            Fragment::False => {
                self.output.push_str("False\n");
            }
            Fragment::True => {
                self.output.push_str("True\n");
            }
            Fragment::PkK { key } => {
                self.output.push_str(&format!("PkK({:?})\n", key));
            }
            Fragment::PkH { key } => {
                self.output.push_str(&format!("PkH({:?})\n", key));
            }
            Fragment::Older { n } => {
                self.output.push_str(&format!("Older({})\n", n));
            }
            Fragment::After { n } => {
                self.output.push_str(&format!("After({})\n", n));
            }
            Fragment::Sha256 { h } => {
                self.output.push_str(&format!("Sha256({:?})\n", h));
            }
            Fragment::Hash256 { h } => {
                self.output.push_str(&format!("Hash256({:?})\n", h));
            }
            Fragment::Ripemd160 { h } => {
                self.output.push_str(&format!("Ripemd160({:?})\n", h));
            }
            Fragment::Hash160 { h } => {
                self.output.push_str(&format!("Hash160({:?})\n", h));
            }
            Fragment::AndOr { x, y, z } => {
                self.output.push_str("AndOr(\n");
                self.indent();
                self.print_node(ctx, ctx.get_node(*x));
                self.print_node(ctx, ctx.get_node(*y));
                self.print_node(ctx, ctx.get_node(*z));
                self.dedent();
                self.write_indent();
                self.output.push_str(")\n");
            }
            Fragment::AndV { x, y } => {
                self.output.push_str("AndV(\n");
                self.indent();
                self.print_node(ctx, ctx.get_node(*x));
                self.print_node(ctx, ctx.get_node(*y));
                self.dedent();
                self.write_indent();
                self.output.push_str(")\n");
            }
            Fragment::AndB { x, y } => {
                self.output.push_str("AndB(\n");
                self.indent();
                self.print_node(ctx, ctx.get_node(*x));
                self.print_node(ctx, ctx.get_node(*y));
                self.dedent();
                self.write_indent();
                self.output.push_str(")\n");
            }
            // Fragment::AndN { x, y } => {
            //     self.output.push_str("AndN(\n");
            //     self.indent();
            //     self.print_node(x);
            //     self.print_node(y);
            //     self.dedent();
            //     self.write_indent();
            //     self.output.push_str(")\n");
            // }
            Fragment::OrB { x, z } => {
                self.output.push_str("OrB(\n");
                self.indent();
                self.print_node(ctx, ctx.get_node(*x));
                self.print_node(ctx, ctx.get_node(*z));
                self.dedent();
                self.write_indent();
                self.output.push_str(")\n");
            }
            Fragment::OrC { x, z } => {
                self.output.push_str("OrC(\n");
                self.indent();
                self.print_node(ctx, ctx.get_node(*x));
                self.print_node(ctx, ctx.get_node(*z));
                self.dedent();
                self.write_indent();
                self.output.push_str(")\n");
            }
            Fragment::OrD { x, z } => {
                self.output.push_str("OrD(\n");
                self.indent();
                self.print_node(ctx, ctx.get_node(*x));
                self.print_node(ctx, ctx.get_node(*z));
                self.dedent();
                self.write_indent();
                self.output.push_str(")\n");
            }
            Fragment::OrI { x, z } => {
                self.output.push_str("OrI(\n");
                self.indent();
                self.print_node(ctx, ctx.get_node(*x));
                self.print_node(ctx, ctx.get_node(*z));
                self.dedent();
                self.write_indent();
                self.output.push_str(")\n");
            }
            Fragment::Thresh { k, xs } => {
                self.output.push_str(&format!("Thresh(k={}, [\n", k));
                self.indent();
                for x in xs {
                    self.print_node(ctx, ctx.get_node(*x));
                }
                self.dedent();
                self.write_indent();
                self.output.push_str("])\n");
            }
            Fragment::Multi { k, keys } => {
                self.output
                    .push_str(&format!("Multi(k={}, keys={:?})\n", k, keys));
            }
            Fragment::MultiA { k, keys } => {
                self.output
                    .push_str(&format!("MultiA(k={}, keys={:?})\n", k, keys));
            }
            Fragment::Identity { identity_type, x } => {
                self.output
                    .push_str(&format!("Identity-{:?}(\n", identity_type));
                self.indent();
                self.print_node(ctx, ctx.get_node(*x));
                self.dedent();
                self.write_indent();
                self.output.push_str(")\n");
            }
            Fragment::Descriptor { descriptor, inner } => {
                self.output
                    .push_str(&format!("Descriptor({:?}, \n", descriptor));
                self.indent();
                self.print_node(ctx, ctx.get_node(*inner));
                self.dedent();
                self.write_indent();
                self.output.push_str(")\n");
            }
        }
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
            self.output.push_str("  ");
        }
    }
}
