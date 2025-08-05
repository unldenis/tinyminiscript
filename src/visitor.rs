//
// NodeVisitor trait
//

use crate::parser::{Context, Node};

#[derive(Debug)]
pub enum VisitorError {
    NodeNotFound(usize),
}

pub trait NodeVisitor<'input, const NODE_BUFFER_SIZE: usize = 256, T = ()> {
    type Error: From<VisitorError>;

    fn visit_node(
        &mut self,
        node: &Node<'input>,
        ctx: &Context<'input, NODE_BUFFER_SIZE>,
    ) -> Result<T, Self::Error>;

    fn visit_node_by_idx(
        &mut self,
        idx: usize,
        ctx: &Context<'input, NODE_BUFFER_SIZE>,
    ) -> Result<T, Self::Error> {
        if let Some(node) = ctx.get_node(idx) {
            self.visit_node(node, ctx)
        } else {
            Err(Self::Error::from(VisitorError::NodeNotFound(idx)))
        }
    }
}
