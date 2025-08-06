use alloc::format;
use alloc::string::String;
use alloc::{boxed::Box, string::ToString, vec::Vec};
use core::fmt::Debug;

use crate::parser::{AST, ASTVisitor, Context, Fragment, IdentityType};

// Miniscript Types

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum MiniscriptType {
    B, // Base
    V, // Verify
    K, // Key
    W, // Wrapped
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Property {
    Z,
    O,
    N,
    D,
    U,
}

#[derive(Debug)]
pub struct TypeInfo {
    base_type: MiniscriptType,
    properties: Vec<Property>,
}

impl TypeInfo {
    pub fn new(base_type: MiniscriptType, properties: Vec<Property>) -> Self {
        Self {
            base_type,
            properties,
        }
    }

    pub fn base_type(&self) -> MiniscriptType {
        self.base_type
    }

    pub fn properties(&self) -> &[Property] {
        &self.properties
    }

    pub fn has_property(&self, property: Property) -> bool {
        self.properties.contains(&property)
    }

    pub fn has_properties(&self, properties: &[Property]) -> bool {
        properties.iter().all(|p| self.has_property(*p))
    }
}

// Type Checker

pub struct CorrectnessPropertiesVisitor {}

impl CorrectnessPropertiesVisitor {
    pub fn new() -> Self {
        Self {}
    }
}

#[derive(Debug)]
pub enum CorrectnessPropertiesVisitorError {
    UnexpectedType { reason: String },
    InvalidThreshold { k: i32 },
    EmptyThreshold,
}

impl ASTVisitor<TypeInfo> for CorrectnessPropertiesVisitor {
    type Error = CorrectnessPropertiesVisitorError;

    fn visit_ast(&mut self, ctx: &Context, node: &AST) -> Result<TypeInfo, Self::Error> {
        match &node.fragment {
            Fragment::False => Ok(TypeInfo::new(
                MiniscriptType::B,
                properties_from_str!("zudh"),
            )),
            Fragment::True => Ok(TypeInfo::new(MiniscriptType::B, properties_from_str!("zu"))),
            Fragment::PkK { key } => Ok(TypeInfo::new(
                MiniscriptType::K,
                properties_from_str!("ondu"),
            )),
            Fragment::PkH { key } => Ok(TypeInfo::new(
                MiniscriptType::K,
                properties_from_str!("ndu"),
            )),
            // Fragment::Pk { key } => Ok(TypeInfo::new(MiniscriptType::K)),
            // Fragment::Pkh { key } => Ok(TypeInfo::new(MiniscriptType::K)),
            Fragment::Older { n } => {
                Ok(TypeInfo::new(MiniscriptType::B, properties_from_str!("z")))
            }
            Fragment::After { n } => {
                Ok(TypeInfo::new(MiniscriptType::B, properties_from_str!("z")))
            }
            Fragment::Sha256 { h } => Ok(TypeInfo::new(
                MiniscriptType::B,
                properties_from_str!("ondu"),
            )),
            Fragment::Hash256 { h } => Ok(TypeInfo::new(
                MiniscriptType::B,
                properties_from_str!("ondu"),
            )),
            Fragment::Ripemd160 { h } => Ok(TypeInfo::new(
                MiniscriptType::B,
                properties_from_str!("ondu"),
            )),
            Fragment::Hash160 { h } => Ok(TypeInfo::new(
                MiniscriptType::B,
                properties_from_str!("ondu"),
            )),

            Fragment::AndOr { x, y, z } => {
                // X is Bdu; Y and Z are both B, K, or V
                let x_type = self.visit_ast(ctx, &x)?;
                let y_type = self.visit_ast(ctx, &y)?;
                let z_type = self.visit_ast(ctx, &z)?;

                if x_type.base_type() != MiniscriptType::B {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "andor(X,Y,Z): X must be type B (Base), but got type {:?}",
                            x_type.base_type()
                        ),
                    });
                }

                if !x_type.has_properties(&properties_from_str!("du")) {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "andor(X,Y,Z): X must have property 'du', but got properties {:?}",
                            x_type.properties()
                        ),
                    });
                }

                if y_type.base_type() != z_type.base_type() {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "andor(X,Y,Z): Y and Z must have the same type, but Y is {:?} and Z is {:?}",
                            y_type.base_type(),
                            z_type.base_type()
                        ),
                    });
                }

                if y_type.base_type() != MiniscriptType::B
                    && y_type.base_type() != MiniscriptType::K
                    && y_type.base_type() != MiniscriptType::V
                {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "andor(X,Y,Z): Y must be type B (Base), K (Key), or V (Verify), but got type {:?}",
                            y_type.base_type()
                        ),
                    });
                }

                // properties: z=zXzYzZ; o=zXoYoZ or oXzYzZ; u=uYuZ; d=dZ
                let mut properties = Vec::new();

                if x_type.has_property(Property::Z)
                    && y_type.has_property(Property::Z)
                    && z_type.has_property(Property::Z)
                {
                    properties.push(Property::Z);
                }
                if (x_type.has_property(Property::Z)
                    && y_type.has_property(Property::O)
                    && z_type.has_property(Property::O))
                    || (x_type.has_property(Property::O)
                        && y_type.has_property(Property::Z)
                        && z_type.has_property(Property::Z))
                {
                    properties.push(Property::O);
                }
                if y_type.has_property(Property::U) && z_type.has_property(Property::U) {
                    properties.push(Property::U);
                }
                if z_type.has_property(Property::D) {
                    properties.push(Property::D);
                }

                Ok(TypeInfo::new(y_type.base_type(), properties))
            }
            Fragment::AndV { x, y } => {
                // X is V; Y is B, K, or V
                let x_type = self.visit_ast(ctx, &x)?;
                let y_type = self.visit_ast(ctx, &y)?;

                if x_type.base_type() != MiniscriptType::V {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "and_v(X,Y): X must be type V (Verify), but got type {:?}",
                            x_type.base_type()
                        ),
                    });
                }

                if y_type.base_type() != MiniscriptType::B
                    && y_type.base_type() != MiniscriptType::K
                    && y_type.base_type() != MiniscriptType::V
                {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "and_v(X,Y): Y must be type B (Base), K (Key), or V (Verify), but got type {:?}",
                            y_type.base_type()
                        ),
                    });
                }

                // properties: z=zXzY; o=zXoY or zYoX; n=nX or zXnY; u=uY
                let mut properties = Vec::new();

                if x_type.has_property(Property::Z) && y_type.has_property(Property::Z) {
                    properties.push(Property::Z);
                }
                if (x_type.has_property(Property::Z) && y_type.has_property(Property::O))
                    || (x_type.has_property(Property::O) && y_type.has_property(Property::Z))
                {
                    properties.push(Property::O);
                }
                if y_type.has_property(Property::N)
                    || (x_type.has_property(Property::Z) && y_type.has_property(Property::N))
                {
                    properties.push(Property::N);
                }
                if y_type.has_property(Property::U) {
                    properties.push(Property::U);
                }

                Ok(TypeInfo::new(y_type.base_type(), properties))
            }
            Fragment::AndB { x, y } => {
                // X is B; Y is W
                let x_type = self.visit_ast(ctx, &x)?;
                let y_type = self.visit_ast(ctx, &y)?;

                if x_type.base_type() != MiniscriptType::B {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "and_b(X,Y): X must be type B (Base), but got type {:?}",
                            x_type.base_type()
                        ),
                    });
                }

                if y_type.base_type() != MiniscriptType::W {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "and_b(X,Y): Y must be type W (Wrapped), but got type {:?}",
                            y_type.base_type()
                        ),
                    });
                }

                // properties: z=zXzY; o=zXoY or zYoX; n=nX or zXnY; d=dXdY; u

                let mut properties = Vec::new();

                if x_type.has_property(Property::Z) && y_type.has_property(Property::Z) {
                    properties.push(Property::Z);
                }
                if (x_type.has_property(Property::Z) && y_type.has_property(Property::O))
                    || (x_type.has_property(Property::O) && y_type.has_property(Property::Z))
                {
                    properties.push(Property::O);
                }
                if y_type.has_property(Property::N)
                    || (x_type.has_property(Property::Z) && y_type.has_property(Property::N))
                {
                    properties.push(Property::N);
                }

                if x_type.has_property(Property::D) && y_type.has_property(Property::D) {
                    properties.push(Property::D);
                }
                properties.push(Property::U);

                Ok(TypeInfo::new(MiniscriptType::B, properties))
            }
            // Fragment::AndN { x, y } => Ok(TypeInfo::new(MiniscriptType::B)),
            Fragment::OrB { x, z } => {
                // X is Bd; Z is Wd
                let x_type = self.visit_ast(ctx, &x)?;
                let z_type = self.visit_ast(ctx, &z)?;

                if x_type.base_type() != MiniscriptType::B {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "or_b(X,Z): X must be type B (Base), but got type {:?}",
                            x_type.base_type()
                        ),
                    });
                }

                if !x_type.has_property(Property::D) {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "or_b(X,Z): X must have property D (Data), but got properties {:?}",
                            x_type.properties()
                        ),
                    });
                }

                if z_type.base_type() != MiniscriptType::W {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "or_b(X,Z): Z must be type W (Wrapped), but got type {:?}",
                            z_type.base_type()
                        ),
                    });
                }

                if !z_type.has_property(Property::D) {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "or_b(X,Z): Z must have property D (Data), but got properties {:?}",
                            z_type.properties()
                        ),
                    });
                }

                // properties: z=zXzZ; o=zXoZ or zZoX; d; u

                let mut properties = Vec::new();

                if x_type.has_property(Property::Z) && z_type.has_property(Property::Z) {
                    properties.push(Property::Z);
                }
                if (x_type.has_property(Property::Z) && z_type.has_property(Property::O))
                    || (x_type.has_property(Property::O) && z_type.has_property(Property::Z))
                {
                    properties.push(Property::O);
                }
                properties.push(Property::D);
                properties.push(Property::U);

                Ok(TypeInfo::new(MiniscriptType::B, properties))
            }
            Fragment::OrC { x, z } => {
                // X is Bdu; Z is V
                let x_type = self.visit_ast(ctx, &x)?;
                let z_type = self.visit_ast(ctx, &z)?;

                if x_type.base_type() != MiniscriptType::B {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "or_c(X,Z): X must be type B (Base), but got type {:?}",
                            x_type.base_type()
                        ),
                    });
                }

                if !x_type.has_properties(&properties_from_str!("du")) {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "or_c(X,Z): X must have properties D (Data) and U (Unknown), but got properties {:?}",
                            x_type.properties()
                        ),
                    });
                }

                if z_type.base_type() != MiniscriptType::V {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "or_c(X,Z): Z must be type V (Verify), but got type {:?}",
                            z_type.base_type()
                        ),
                    });
                }

                // properties: z=zXzZ; o=oXzZ

                let mut properties = Vec::new();

                if x_type.has_property(Property::Z) && z_type.has_property(Property::Z) {
                    properties.push(Property::Z);
                }
                if x_type.has_property(Property::O) && z_type.has_property(Property::Z) {
                    properties.push(Property::O);
                }
                Ok(TypeInfo::new(MiniscriptType::V, properties))
            }
            Fragment::OrD { x, z } => {
                // X is Bdu; Z is B
                let x_type = self.visit_ast(ctx, &x)?;
                let z_type = self.visit_ast(ctx, &z)?;

                if x_type.base_type() != MiniscriptType::B {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "or_d(X,Z): X must be type B (Base), but got type {:?}",
                            x_type.base_type()
                        ),
                    });
                }

                if !x_type.has_properties(&properties_from_str!("du")) {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "or_d(X,Z): X must have properties D (Data) and U (Unknown), but got properties {:?}",
                            x_type.properties()
                        ),
                    });
                }

                if z_type.base_type() != MiniscriptType::B {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "or_d(X,Z): Z must be type B (Base), but got type {:?}",
                            z_type.base_type()
                        ),
                    });
                }

                // properties: z=zXzZ; o=oXzZ; d=dZ; u=uZ

                let mut properties = Vec::new();

                if x_type.has_property(Property::Z) && z_type.has_property(Property::Z) {
                    properties.push(Property::Z);
                }
                if x_type.has_property(Property::O) && z_type.has_property(Property::Z) {
                    properties.push(Property::O);
                }
                if z_type.has_property(Property::D) {
                    properties.push(Property::D);
                }

                if z_type.has_property(Property::U) {
                    properties.push(Property::U);
                }

                Ok(TypeInfo::new(MiniscriptType::B, properties))
            }
            Fragment::OrI { x, z } => {
                // both are B, K, or V
                let x_type = self.visit_ast(ctx, &x)?;
                let z_type = self.visit_ast(ctx, &z)?;

                if x_type.base_type() != z_type.base_type() {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "or_i(X,Z): X and Z must have the same type, but X is {:?} and Z is {:?}",
                            x_type.base_type(),
                            z_type.base_type()
                        ),
                    });
                }

                if x_type.base_type() != MiniscriptType::B
                    && x_type.base_type() != MiniscriptType::K
                    && x_type.base_type() != MiniscriptType::V
                {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "or_i(X,Z): X must be type B (Base), K (Key), or V (Verify), but got type {:?}",
                            x_type.base_type()
                        ),
                    });
                }

                // properties: o=zXzZ; u=uXuZ; d=dX or dZ

                let mut properties = Vec::new();

                if x_type.has_property(Property::Z) && z_type.has_property(Property::Z) {
                    properties.push(Property::Z);
                }
                if x_type.has_property(Property::U) && z_type.has_property(Property::U) {
                    properties.push(Property::U);
                }
                if x_type.has_property(Property::D) || z_type.has_property(Property::D) {
                    properties.push(Property::D);
                }

                Ok(TypeInfo::new(x_type.base_type(), properties))
            }
            Fragment::Thresh { k, xs } => {
                // 1 ≤ k ≤ n; X1 is Bdu; others are Wdu
                let k = *k;
                if k < 1 {
                    return Err(CorrectnessPropertiesVisitorError::InvalidThreshold { k });
                }

                if xs.len() < k as usize {
                    return Err(CorrectnessPropertiesVisitorError::InvalidThreshold { k });
                }

                if xs.is_empty() {
                    return Err(CorrectnessPropertiesVisitorError::EmptyThreshold);
                }

                let mut first_type = true;
                for (i, x) in xs.iter().enumerate() {
                    let x_type = self.visit_ast(ctx, &x)?;
                    if first_type {
                        first_type = false;

                        if x_type.base_type() != MiniscriptType::B {
                            return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                                reason: format!(
                                    "thresh(k,X1,...,Xn): X1 must be type B (Base), but got type {:?}",
                                    x_type.base_type()
                                ),
                            });
                        }

                        if !x_type.has_properties(&properties_from_str!("du")) {
                            return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                                reason: format!(
                                    "thresh(k,X1,...,Xn): X{} must have properties D (Data) and U (Unknown), but got properties {:?}",
                                    i,
                                    x_type.properties()
                                ),
                            });
                        }
                    } else {
                        if x_type.base_type() != MiniscriptType::W {
                            return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                                reason: format!(
                                    "thresh(k,X1,...,Xn): X{} must be type W (Wrapped), but got type {:?}",
                                    i,
                                    x_type.base_type()
                                ),
                            });
                        }

                        if !x_type.has_properties(&properties_from_str!("du")) {
                            return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                                reason: format!(
                                    "thresh(k,X1,...,Xn): X{} must have properties D (Data) and U (Unknown), but got properties {:?}",
                                    i,
                                    x_type.properties()
                                ),
                            });
                        }
                    }
                }

                // properties: z=all are z; o=all are z except one is o; d; u

                let mut properties = Vec::new();

                let mut z_count = 0;
                let mut o_count = 0;
                for x in xs {
                    let x_type = self.visit_ast(ctx, &x)?;
                    if x_type.has_property(Property::Z) {
                        z_count += 1;
                    } else if x_type.has_property(Property::O) {
                        o_count += 1;
                    }
                }
                if z_count == xs.len() {
                    properties.push(Property::Z);
                }
                if o_count == 1 && z_count == xs.len() - 1 {
                    properties.push(Property::O);
                }
                properties.push(Property::D);
                properties.push(Property::U);
                Ok(TypeInfo::new(MiniscriptType::B, properties))
            }
            Fragment::Multi { k, keys } => {
                // 1 ≤ k ≤ n
                let k = *k;
                if k < 1 {
                    return Err(CorrectnessPropertiesVisitorError::InvalidThreshold { k });
                }

                if keys.len() < k as usize {
                    return Err(CorrectnessPropertiesVisitorError::InvalidThreshold { k });
                }

                if keys.is_empty() {
                    return Err(CorrectnessPropertiesVisitorError::EmptyThreshold);
                }

                Ok(TypeInfo::new(
                    MiniscriptType::B,
                    properties_from_str!("ndu"),
                ))
            }
            Fragment::MultiA { k, keys } => {
                // 1 ≤ k ≤ n
                let k = *k;
                if k < 1 {
                    return Err(CorrectnessPropertiesVisitorError::InvalidThreshold { k });
                }

                if keys.len() < k as usize {
                    return Err(CorrectnessPropertiesVisitorError::InvalidThreshold { k });
                }

                if keys.is_empty() {
                    return Err(CorrectnessPropertiesVisitorError::EmptyThreshold);
                }

                Ok(TypeInfo::new(MiniscriptType::B, properties_from_str!("du")))
            }
            Fragment::Identity { identity_type, x } => {
                let x_type = self.visit_ast(ctx, &x)?;

                match identity_type {
                    IdentityType::A => {
                        // X is B
                        if x_type.base_type() != MiniscriptType::B {
                            return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                                reason: format!(
                                    "a:X: X must be type B (Base), but got type {:?}",
                                    x_type.base_type()
                                ),
                            });
                        }

                        // properties: d=dX; u=uX
                        let mut properties = Vec::new();
                        if x_type.has_property(Property::D) {
                            properties.push(Property::D);
                        }
                        if x_type.has_property(Property::U) {
                            properties.push(Property::U);
                        }
                        Ok(TypeInfo::new(MiniscriptType::W, properties))
                    }
                    IdentityType::S => {
                        // X is Bo
                        if x_type.base_type() != MiniscriptType::B {
                            return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                                reason: format!(
                                    "s:X: X must be type B (Base), but got type {:?}",
                                    x_type.base_type()
                                ),
                            });
                        }

                        // properties: d=dX; u=uX
                        let mut properties = Vec::new();
                        if x_type.has_property(Property::D) {
                            properties.push(Property::D);
                        }
                        if x_type.has_property(Property::U) {
                            properties.push(Property::U);
                        }
                        Ok(TypeInfo::new(MiniscriptType::W, properties))
                    }
                    IdentityType::C => {
                        // X is K
                        if x_type.base_type() != MiniscriptType::K {
                            return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                                reason: format!(
                                    "c:X: X must be type K (Key), but got type {:?}",
                                    x_type.base_type()
                                ),
                            });
                        }

                        // properties: o=oX; n=nX; d=dX; u
                        let mut properties = Vec::new();
                        if x_type.has_property(Property::O) {
                            properties.push(Property::O);
                        }
                        if x_type.has_property(Property::N) {
                            properties.push(Property::N);
                        }
                        if x_type.has_property(Property::D) {
                            properties.push(Property::D);
                        }
                        properties.push(Property::U);
                        Ok(TypeInfo::new(MiniscriptType::B, properties))
                    }

                    IdentityType::D => {
                        // X is Vz
                        if x_type.base_type() != MiniscriptType::V {
                            return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                                reason: format!(
                                    "d:X: X must be type V (Verify), but got type {:?}",
                                    x_type.base_type()
                                ),
                            });
                        }

                        // properties: o; n; d; (Tapscript only) u
                        let mut properties = Vec::new();
                        properties.push(Property::O);
                        properties.push(Property::N);
                        properties.push(Property::D);
                        properties.push(Property::U); // TODO: Tapscript only

                        Ok(TypeInfo::new(MiniscriptType::B, properties))
                    }

                    IdentityType::V => {
                        // X is B
                        if x_type.base_type() != MiniscriptType::B {
                            return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                                reason: format!(
                                    "v:X: X must be type B (Base), but got type {:?}",
                                    x_type.base_type()
                                ),
                            });
                        }

                        // properties: z=zX; o=oX; n=nX
                        let mut properties = Vec::new();
                        if x_type.has_property(Property::Z) {
                            properties.push(Property::Z);
                        }
                        if x_type.has_property(Property::O) {
                            properties.push(Property::O);
                        }
                        if x_type.has_property(Property::N) {
                            properties.push(Property::N);
                        }
                        Ok(TypeInfo::new(MiniscriptType::V, properties))
                    }

                    IdentityType::J => {
                        // X is Bn
                        if x_type.base_type() != MiniscriptType::B {
                            return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                                reason: format!(
                                    "j:X: X must be type B (Base), but got type {:?}",
                                    x_type.base_type()
                                ),
                            });
                        }

                        // properties: o=oX; n; d; u=uX

                        let mut properties = Vec::new();
                        if x_type.has_property(Property::O) {
                            properties.push(Property::O);
                        }
                        properties.push(Property::N);
                        properties.push(Property::D);
                        if x_type.has_property(Property::U) {
                            properties.push(Property::U);
                        }
                        Ok(TypeInfo::new(MiniscriptType::B, properties))
                    }

                    IdentityType::N => {
                        // X is B
                        if x_type.base_type() != MiniscriptType::B {
                            return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                                reason: format!(
                                    "n:X: X must be type B (Base), but got type {:?}",
                                    x_type.base_type()
                                ),
                            });
                        }

                        // properties: z=zX; o=oX; n=nX; d=dX; u

                        let mut properties = Vec::new();
                        if x_type.has_property(Property::Z) {
                            properties.push(Property::Z);
                        }
                        if x_type.has_property(Property::O) {
                            properties.push(Property::O);
                        }
                        if x_type.has_property(Property::N) {
                            properties.push(Property::N);
                        }
                        if x_type.has_property(Property::D) {
                            properties.push(Property::D);
                        }
                        properties.push(Property::U);

                        Ok(TypeInfo::new(MiniscriptType::B, properties))
                    }
                }
            }
        }
    }
}
