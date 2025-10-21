use core::marker::PhantomData;

use crate::descriptor::{self, Descriptor, DescriptorValidator};
use crate::parser::keys::KeyToken;
use crate::parser::{Fragment, NodeIndex};
use crate::script::{AddressBuilderError, ScriptBuilderError};
use crate::type_checker::CorrectnessPropertiesVisitor;
use crate::{Vec, parser::AST};
use crate::{limits, parser, type_checker};

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
                Fragment::RawPkH { key } => callback(key),
                Fragment::RawTr { key, .. } => {
                    callback(key);
                }
                Fragment::RawPk { key } => {
                    callback(key);
                }
                _ => (),
            });
    }

    /// Iterate over all the keys.
    pub fn iterate_keys(&self, mut callback: impl FnMut(&KeyToken)) {
        self.nodes.iter().for_each(|node| match &node.fragment {
            Fragment::PkK { key } => callback(key),
            Fragment::PkH { key } => callback(key),
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
            Fragment::RawPkH { key } => callback(key),
            Fragment::RawTr { key, .. } => {
                callback(key);
            }
            Fragment::RawPk { key } => {
                callback(key);
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
    pub fn build_address<'a>(&self, network: Network) -> Result<Address, AddressBuilderError<'a>> {
        crate::script::build_address(self, network)
    }
}

/// Errors that can occur during miniscript parsing, validation, or script building.
///
/// When the `debug` feature is enabled, this enum implements [`Debug`] for easier
/// debugging and error reporting in development environments.
#[cfg_attr(feature = "debug", derive(Debug))]
pub enum ContextError<'a> {
    /// Error occurred during parsing of the miniscript string
    ParserError(parser::ParseError<'a>),
    /// Error occurred during type checking and correctness validation
    TypeCheckerError(type_checker::CorrectnessPropertiesVisitorError),
    /// Error occurred during descriptor validation
    DescriptorVisitorError(descriptor::DescriptorVisitorError),
    /// Error occurred during script size checking
    LimitsError(limits::LimitsError),
}

/// Parse and validate a miniscript string, returning the parsed context and generated Bitcoin script.
///
/// This function performs a complete validation pipeline:
/// 1. Parses the miniscript string into an AST
/// 2. Type checks the AST for correctness properties
/// 3. Validates the descriptor structure
/// 4. Generates the corresponding Bitcoin script
///
/// # Arguments
///
/// * `script` - The miniscript string to parse and validate
///
/// # Returns
///
/// Returns `Ok((Context, ScriptBuf))` on success, where:
/// - [`Context`] contains the parsed AST and metadata
/// - [`ScriptBuf`] is the generated Bitcoin script
///
/// Returns `Err(MiniscriptError)` if parsing, validation, or script generation fails.
///
/// # Examples
///
/// ```rust
/// use tinyminiscript::Context;
///
/// let result = Context::try_from("pk(02e79c4c8b3c8b3c8b3c8b3c8b3c8b3c8b3c8b3c8b3c8b3c8b3c8b3c8b3c8b3)");
/// match result {
///     Ok(ctx) => {
///         let script = ctx.build_script().unwrap();
///         println!("Generated script: {:?}", script);
///     }
///     Err(e) => eprintln!("Parse error: {:?}", e),
/// }
/// ```
impl<'a> TryFrom<&'a str> for Context {
    type Error = ContextError<'a>;
    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let ctx = parser::parse(value).map_err(ContextError::ParserError)?;

        // Type check the AST for correctness properties
        let type_info = CorrectnessPropertiesVisitor::new()
            .visit(&ctx)
            .map_err(ContextError::TypeCheckerError)?;

        // Validate the descriptor structure
        let _: () = DescriptorValidator::new()
            .validate(&ctx)
            .map_err(ContextError::DescriptorVisitorError)?;

        // Check the recursion depth
        limits::check_recursion_depth(type_info.tree_height).map_err(ContextError::LimitsError)?;

        // Check the script size
        limits::check_script_size(&ctx.descriptor(), type_info.pk_cost)
            .map_err(ContextError::LimitsError)?;

        Ok(ctx)
    }
}
