use core::marker::PhantomData;

use crate::descriptor::Descriptor;
use crate::parser::keys::KeyToken;
use crate::parser::{Fragment, NodeIndex};
use crate::script::ScriptBuilderError;
use crate::{Vec, parser::AST};

use alloc::string::String;
use bitcoin::{Address, Network, ScriptBuf};

// AST Visitor trait for visiting the AST.
pub(crate) trait ASTVisitor<T> {
    type Error;

    fn visit_ast(&mut self, ctx: &Context, node: &AST) -> Result<T, Self::Error>;

    #[inline]
    fn visit_ast_by_index(&mut self, ctx: &Context, index: NodeIndex) -> Result<T, Self::Error> {
        self.visit_ast(ctx, &ctx.nodes[index as usize])
    }

    #[inline]
    fn visit(&mut self, ctx: &Context) -> Result<T, Self::Error> {
        self.visit_ast(ctx, &ctx.get_root())
    }
}

/// Context for miniscript expressions.
pub struct Context {
    nodes: Vec<AST>,
    root: AST,
    top_level_descriptor: Descriptor,
    inner_descriptor: Descriptor,
}

impl Context {
    pub(crate) fn new(
        nodes: Vec<AST>,
        root: AST,
        top_level_descriptor: Descriptor,
        inner_descriptor: Descriptor,
    ) -> Self {
        Self {
            nodes,
            root,
            top_level_descriptor,
            inner_descriptor,
        }
    }

    /// Get all the nodes in the AST.
    pub fn get_nodes(&self) -> &[AST] {
        &self.nodes[..]
    }

    /// Get the root node of the AST.
    pub fn get_root(&self) -> &AST {
        &self.root
    }

    /// Get the top level descriptor of the AST.
    pub fn top_level_descriptor(&self) -> Descriptor {
        self.top_level_descriptor.clone()
    }

    /// Get the inner descriptor of the AST.
    pub fn descriptor(&self) -> Descriptor {
        self.inner_descriptor.clone()
    }

    /// Check if the top level descriptor is wrapped.
    pub fn is_wrapped(&self) -> bool {
        self.top_level_descriptor == Descriptor::Sh
    }

    /// Get a node by index.
    pub fn get_node(&self, index: NodeIndex) -> &AST {
        &self.nodes[index as usize]
    }

    /// Satisfy the context with a satisfier.
    #[cfg(feature = "satisfy")]
    pub fn satisfy(
        &self,
        satisfier: &dyn crate::satisfy::Satisfier,
    ) -> Result<crate::satisfy::Satisfactions, crate::satisfy::SatisfyError> {
        crate::satisfy::satisfy(self, satisfier, &self.get_root())
    }

    /// Iterate over all the keys mutably.
    /// Not using a Visitor pattern because it's not needed for the current use case.
    pub fn iterate_keys_mut(&mut self, mut callback: impl FnMut(&mut KeyToken)) {
        self.nodes
            .iter_mut()
            .for_each(|node| match &mut node.fragment {
                Fragment::PkK { key } => callback(key),
                Fragment::PkH { key } => callback(key),
                Fragment::RawPkH { key } => callback(key),
                Fragment::Multi { keys, .. } => {
                    for key in keys.iter_mut() {
                        callback(key);
                    }
                }
                Fragment::MultiA { keys, .. } => {
                    for key in keys.iter_mut() {
                        callback(key);
                    }
                }
                _ => (),
            });
    }

    /// Iterate over all the keys.
    pub fn iterate_keys(&self, mut callback: impl FnMut(&KeyToken)) {
        self.nodes.iter().for_each(|node| match &node.fragment {
            Fragment::PkK { key } => callback(key),
            Fragment::PkH { key } => callback(key),
            Fragment::RawPkH { key } => callback(key),
            Fragment::Multi { keys, .. } => {
                for key in keys.iter() {
                    callback(key);
                }
            }
            Fragment::MultiA { keys, .. } => {
                for key in keys.iter() {
                    callback(key);
                }
            }
            _ => (),
        });
    }

    /// Derive all the keys in the AST.
    pub fn derive(&mut self, index: u32) -> Result<(), String> {
        for node in &mut self.nodes {
            match &mut node.fragment {
                Fragment::PkK { key } | Fragment::PkH { key } | Fragment::RawPkH { key } => {
                    let derived = key.derive(index)?;
                    *key = derived;
                }
                Fragment::Multi { keys, k } => {
                    for key in keys.iter_mut() {
                        let derived = key.derive(index)?;
                        *key = derived;
                    }
                }
                Fragment::MultiA { keys, k } => {
                    for key in keys.iter_mut() {
                        let derived = key.derive(index)?;
                        *key = derived;
                    }
                }
                _ => (),
            }
        }
        Ok(())
    }

    /// Serialize the AST to a string.
    pub fn serialize(&self) -> String {
        let mut serializer = crate::utils::serialize::Serializer::new();
        serializer.serialize(self)
    }

    /// Build the script from the AST.
    pub fn build_script<'a>(&self) -> Result<ScriptBuf, ScriptBuilderError<'a>> {
        crate::script::build_script(self)
    }

    /// Build the address from the AST.
    pub fn build_address<'a>(&self, network: Network) -> Result<Address, ScriptBuilderError<'a>> {
        crate::script::build_address(self, network)
    }
}
