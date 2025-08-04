//
// NodeVisitor trait
//

use crate::parser::{Context, Node};

pub trait NodeVisitor<'input, const NODE_BUFFER_SIZE: usize = 256> {
    fn visit_node(&mut self, node: &Node<'input>, ctx: &Context<'input, NODE_BUFFER_SIZE>);

    fn visit_node_by_idx(&mut self, idx: usize, ctx: &Context<'input, NODE_BUFFER_SIZE>) {
        if let Some(node) = ctx.get_node(idx) {
            self.visit_node(node, ctx);
        }
    }
}
