use core::fmt::Debug;

use crate::{
    error::MiniscriptError,
    parser::{Context, Fragment, IdentityType, MiniscriptType, Node},
};

//
// NodeVisitor trait
//

pub trait NodeVisitor<'input, const NODE_BUFFER_SIZE: usize = 256, T = ()> {
    type Error;

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
        self.visit_node(ctx.get_node(idx), ctx)
    }
}

//
// Correctness Properties Visitor
//

pub struct CorrectnessPropertiesVisitor {}

impl CorrectnessPropertiesVisitor {
    pub fn new() -> Self {
        Self {}
    }
}

pub enum CorrectnessPropertiesVisitorError {
    UnexpectedType { reason: &'static str },
    InvalidThreshold { k: u32, n: u32 },
}

impl Debug for CorrectnessPropertiesVisitorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CorrectnessPropertiesVisitorError::UnexpectedType { reason } => {
                write!(f, "Unexpected type: {}", reason)
            }
            CorrectnessPropertiesVisitorError::InvalidThreshold { k, n } => {
                write!(f, "Invalid threshold: {} of {}", k, n)
            }
        }
    }
}

impl<'input, const NODE_BUFFER_SIZE: usize> NodeVisitor<'input, NODE_BUFFER_SIZE, ()>
    for CorrectnessPropertiesVisitor
{
    type Error = MiniscriptError<'input, CorrectnessPropertiesVisitorError>;

    fn visit_node(
        &mut self,
        node: &Node<'input>,
        ctx: &Context<'input, NODE_BUFFER_SIZE>,
    ) -> Result<(), Self::Error> {
        match &node.fragment {
            Fragment::AndOr { x, y, z } => {
                // X is Bdu; Y and Z are both B, K, or V
                let x_node = ctx.get_node(*x);
                let y_node = ctx.get_node(*y);
                let z_node = ctx.get_node(*z);

                let x_type = x_node.type_info.base_type().clone();
                let y_type = y_node.type_info.base_type().clone();
                let z_type = z_node.type_info.base_type().clone();

                if x_type != MiniscriptType::B {
                    return Err(MiniscriptError::new(
                        ctx.input,
                        x_node.position.clone(),
                        CorrectnessPropertiesVisitorError::UnexpectedType {
                            reason: "X must be a B type",
                        },
                    ));
                }

                if y_type != z_type {
                    return Err(MiniscriptError::new(
                        ctx.input,
                        z_node.position.clone(),
                        CorrectnessPropertiesVisitorError::UnexpectedType {
                            reason: "Y and Z must be the same type",
                        },
                    ));
                }

                if y_type != MiniscriptType::B
                    && y_type != MiniscriptType::V
                    && y_type != MiniscriptType::K
                {
                    return Err(MiniscriptError::new(
                        ctx.input,
                        y_node.position.clone(),
                        CorrectnessPropertiesVisitorError::UnexpectedType {
                            reason: "Y and Z must be a B type, V type, or K type",
                        },
                    ));
                }

                Ok(())
            }
            Fragment::AndV { x, y } => {
                // X is V; Y is B, K, or V
                let x_node = ctx.get_node(*x);
                let y_node = ctx.get_node(*y);

                let x_type = x_node.type_info.base_type().clone();
                let y_type = y_node.type_info.base_type().clone();

                if x_type != MiniscriptType::V {
                    return Err(MiniscriptError::new(
                        ctx.input,
                        x_node.position.clone(),
                        CorrectnessPropertiesVisitorError::UnexpectedType {
                            reason: "X must be a V type",
                        },
                    ));
                }

                if y_type != MiniscriptType::B
                    && y_type != MiniscriptType::V
                    && y_type != MiniscriptType::K
                {
                    return Err(MiniscriptError::new(
                        ctx.input,
                        y_node.position.clone(),
                        CorrectnessPropertiesVisitorError::UnexpectedType {
                            reason: "Y must be a B type, V type, or K type",
                        },
                    ));
                }

                Ok(())
            }
            Fragment::AndB { x, y } => {
                // X is B; Y is W
                let x_node = ctx.get_node(*x);
                let y_node = ctx.get_node(*y);

                let x_type = x_node.type_info.base_type().clone();
                let y_type = y_node.type_info.base_type().clone();

                if x_type != MiniscriptType::B {
                    return Err(MiniscriptError::new(
                        ctx.input,
                        x_node.position.clone(),
                        CorrectnessPropertiesVisitorError::UnexpectedType {
                            reason: "X must be a B type",
                        },
                    ));
                }

                if y_type != MiniscriptType::W {
                    return Err(MiniscriptError::new(
                        ctx.input,
                        y_node.position.clone(),
                        CorrectnessPropertiesVisitorError::UnexpectedType {
                            reason: "Y must be a W type",
                        },
                    ));
                }

                Ok(())
            }
            Fragment::OrB { x, z } => {
                // X is Bd; Z is Wd
                let x_node = ctx.get_node(*x);
                let z_node = ctx.get_node(*z);

                let x_type = x_node.type_info.base_type().clone();
                let z_type = z_node.type_info.base_type().clone();

                if x_type != MiniscriptType::B {
                    return Err(MiniscriptError::new(
                        ctx.input,
                        x_node.position.clone(),
                        CorrectnessPropertiesVisitorError::UnexpectedType {
                            reason: "X must be a B type",
                        },
                    ));
                }

                if z_type != MiniscriptType::W {
                    return Err(MiniscriptError::new(
                        ctx.input,
                        z_node.position.clone(),
                        CorrectnessPropertiesVisitorError::UnexpectedType {
                            reason: "Z must be a W type",
                        },
                    ));
                }

                Ok(())
            }
            Fragment::OrC { x, z } => {
                // X is Bdu; Z is V
                let x_node = ctx.get_node(*x);
                let z_node = ctx.get_node(*z);

                let x_type = x_node.type_info.base_type().clone();
                let z_type = z_node.type_info.base_type().clone();

                if x_type != MiniscriptType::B {
                    return Err(MiniscriptError::new(
                        ctx.input,
                        x_node.position.clone(),
                        CorrectnessPropertiesVisitorError::UnexpectedType {
                            reason: "X must be a B type",
                        },
                    ));
                }

                if z_type != MiniscriptType::V {
                    return Err(MiniscriptError::new(
                        ctx.input,
                        z_node.position.clone(),
                        CorrectnessPropertiesVisitorError::UnexpectedType {
                            reason: "Z must be a V type",
                        },
                    ));
                }

                Ok(())
            }
            Fragment::OrD { x, z } => {
                // X is Bdu; Z is B
                let x_node = ctx.get_node(*x);
                let z_node = ctx.get_node(*z);

                let x_type = x_node.type_info.base_type().clone();
                let z_type = z_node.type_info.base_type().clone();

                if x_type != MiniscriptType::B {
                    return Err(MiniscriptError::new(
                        ctx.input,
                        x_node.position.clone(),
                        CorrectnessPropertiesVisitorError::UnexpectedType {
                            reason: "X must be a B type",
                        },
                    ));
                }

                if z_type != MiniscriptType::B {
                    return Err(MiniscriptError::new(
                        ctx.input,
                        z_node.position.clone(),
                        CorrectnessPropertiesVisitorError::UnexpectedType {
                            reason: "Z must be a B type",
                        },
                    ));
                }

                Ok(())
            }
            Fragment::OrI { x, z } => {
                // both are B, K, or V
                let x_node = ctx.get_node(*x);
                let z_node = ctx.get_node(*z);

                let x_type = x_node.type_info.base_type().clone();
                let z_type = z_node.type_info.base_type().clone();

                if x_type != MiniscriptType::B
                    && x_type != MiniscriptType::K
                    && x_type != MiniscriptType::V
                {
                    return Err(MiniscriptError::new(
                        ctx.input,
                        x_node.position.clone(),
                        CorrectnessPropertiesVisitorError::UnexpectedType {
                            reason: "X must be a B type, K type, or V type",
                        },
                    ));
                }

                if z_type != MiniscriptType::B
                    && z_type != MiniscriptType::K
                    && z_type != MiniscriptType::V
                {
                    return Err(MiniscriptError::new(
                        ctx.input,
                        z_node.position.clone(),
                        CorrectnessPropertiesVisitorError::UnexpectedType {
                            reason: "Z must be a B type, K type, or V type",
                        },
                    ));
                }

                Ok(())
            }
            Fragment::Thresh { k, xs } => {
                // 1 ≤ k ≤ n; X1 is Bdu; others are Wdu

                if k.value < 1 || k.value > xs.len() as u32 {
                    return Err(MiniscriptError::new(
                        ctx.input,
                        node.position.clone(),
                        CorrectnessPropertiesVisitorError::InvalidThreshold {
                            k: k.value,
                            n: xs.len() as u32,
                        },
                    ));
                }

                let mut first_node = true;
                for ele in xs.iter() {
                    let node = ctx.get_node(*ele);
                    let node_type = node.type_info.base_type().clone();

                    if first_node {
                        first_node = false;
                        if node_type != MiniscriptType::B {
                            return Err(MiniscriptError::new(
                                ctx.input,
                                node.position.clone(),
                                CorrectnessPropertiesVisitorError::UnexpectedType {
                                    reason: "The first node must be a B type",
                                },
                            ));
                        }
                    } else {
                        if node_type != MiniscriptType::W {
                            return Err(MiniscriptError::new(
                                ctx.input,
                                node.position.clone(),
                                CorrectnessPropertiesVisitorError::UnexpectedType {
                                    reason: "All nodes must be W types",
                                },
                            ));
                        }
                    }
                }
                Ok(())
            }
            Fragment::Multi { k, keys } => {
                // 1 ≤ k ≤ n
                if k.value < 1 || k.value > keys.len() as u32 {
                    return Err(MiniscriptError::new(
                        ctx.input,
                        node.position.clone(),
                        CorrectnessPropertiesVisitorError::InvalidThreshold {
                            k: k.value,
                            n: keys.len() as u32,
                        },
                    ));
                }

                Ok(())
            }
            Fragment::MultiA { k, keys } => {
                // 1 ≤ k ≤ n
                if k.value < 1 || k.value > keys.len() as u32 {
                    return Err(MiniscriptError::new(
                        ctx.input,
                        node.position.clone(),
                        CorrectnessPropertiesVisitorError::InvalidThreshold {
                            k: k.value,
                            n: keys.len() as u32,
                        },
                    ));
                }

                Ok(())
            }
            Fragment::Identity { identity_type, x } => {
                match identity_type {
                    IdentityType::A => {
                        // X is B
                        let x_node = ctx.get_node(*x);

                        let x_type = x_node.type_info.base_type().clone();

                        if x_type != MiniscriptType::B {
                            return Err(MiniscriptError::new(
                                ctx.input,
                                x_node.position.clone(),
                                CorrectnessPropertiesVisitorError::UnexpectedType {
                                    reason: "X must be a B type",
                                },
                            ));
                        }

                        Ok(())
                    }
                    IdentityType::S => {
                        // X is Bo
                        let x_node = ctx.get_node(*x);

                        let x_type = x_node.type_info.base_type().clone();

                        if x_type != MiniscriptType::B {
                            return Err(MiniscriptError::new(
                                ctx.input,
                                x_node.position.clone(),
                                CorrectnessPropertiesVisitorError::UnexpectedType {
                                    reason: "X must be a B type",
                                },
                            ));
                        }

                        Ok(())
                    }
                    IdentityType::C => {
                        // X is K
                        let x_node = ctx.get_node(*x);

                        let x_type = x_node.type_info.base_type().clone();

                        if x_type != MiniscriptType::K {
                            return Err(MiniscriptError::new(
                                ctx.input,
                                x_node.position.clone(),
                                CorrectnessPropertiesVisitorError::UnexpectedType {
                                    reason: "X must be a K type",
                                },
                            ));
                        }

                        Ok(())
                    }
                    IdentityType::D => {
                        // X is Vz
                        let x_node = ctx.get_node(*x);

                        let x_type = x_node.type_info.base_type().clone();

                        if x_type != MiniscriptType::V {
                            return Err(MiniscriptError::new(
                                ctx.input,
                                x_node.position.clone(),
                                CorrectnessPropertiesVisitorError::UnexpectedType {
                                    reason: "X must be a V type",
                                },
                            ));
                        }

                        Ok(())
                    }
                    IdentityType::V => {
                        // X is B
                        let x_node = ctx.get_node(*x);

                        let x_type = x_node.type_info.base_type().clone();

                        if x_type != MiniscriptType::B {
                            return Err(MiniscriptError::new(
                                ctx.input,
                                x_node.position.clone(),
                                CorrectnessPropertiesVisitorError::UnexpectedType {
                                    reason: "X must be a B type",
                                },
                            ));
                        }

                        Ok(())
                    }
                    IdentityType::J => {
                        // X is Bn
                        let x_node = ctx.get_node(*x);

                        let x_type = x_node.type_info.base_type().clone();

                        if x_type != MiniscriptType::B {
                            return Err(MiniscriptError::new(
                                ctx.input,
                                x_node.position.clone(),
                                CorrectnessPropertiesVisitorError::UnexpectedType {
                                    reason: "X must be a B type",
                                },
                            ));
                        }

                        Ok(())
                    }
                    IdentityType::N => {
                        // X is B
                        let x_node = ctx.get_node(*x);
                        let x_type = x_node.type_info.base_type().clone();

                        if x_type != MiniscriptType::B {
                            return Err(MiniscriptError::new(
                                ctx.input,
                                x_node.position.clone(),
                                CorrectnessPropertiesVisitorError::UnexpectedType {
                                    reason: "X must be a B type",
                                },
                            ));
                        }

                        Ok(())
                    }
                }
            }

            Fragment::False => Ok(()),
            Fragment::True => Ok(()),
            Fragment::PkK { key } => Ok(()),
            Fragment::PkH { key } => Ok(()),
            Fragment::Pk { key } => Ok(()),
            Fragment::Pkh { key } => Ok(()),
            Fragment::Older { n } => Ok(()),
            Fragment::After { n } => Ok(()),
            Fragment::Sha256 { h } => Ok(()),
            Fragment::Hash256 { h } => Ok(()),
            Fragment::Ripemd160 { h } => Ok(()),
            Fragment::Hash160 { h } => Ok(()),
            Fragment::AndN { x, y } => Ok(()),
        }
    }
}
