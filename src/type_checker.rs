use alloc::format;
use alloc::string::String;
use alloc::{boxed::Box, string::ToString, vec::Vec};
use core::fmt::Debug;

use crate::parser::{AST, ASTVisitor, Fragment, IdentityType};

// Miniscript Types as bit flags

/// Base
pub const MINISCRIPT_TYPE_B: u8 = 1 << 0;
/// Verify
pub const MINISCRIPT_TYPE_V: u8 = 1 << 1;
/// Key
pub const MINISCRIPT_TYPE_K: u8 = 1 << 2;
/// Wrapped
pub const MINISCRIPT_TYPE_W: u8 = 1 << 3;

// Properties as bit flags

pub const PROPERTY_Z: u8 = 1 << 0;
pub const PROPERTY_O: u8 = 1 << 1;
pub const PROPERTY_N: u8 = 1 << 2;
pub const PROPERTY_D: u8 = 1 << 3;
pub const PROPERTY_U: u8 = 1 << 4;

#[derive(Debug)]
pub struct TypeInfo {
    base_type: u8,
    properties: u8,
}

impl TypeInfo {
    pub fn new(base_type: u8, properties: u8) -> Self {
        Self {
            base_type,
            properties,
        }
    }

    pub fn base_type(&self) -> u8 {
        self.base_type
    }

    pub fn properties(&self) -> u8 {
        self.properties
    }

    pub fn has_property(&self, property: u8) -> bool {
        (self.properties & property) != 0
    }

    pub fn has_properties(&self, properties: u8) -> bool {
        (self.properties & properties) == properties
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

    fn visit_ast(&mut self, node: &AST) -> Result<TypeInfo, Self::Error> {
        match &node.fragment {
            Fragment::False => Ok(TypeInfo::new(
                MINISCRIPT_TYPE_B,
                PROPERTY_Z | PROPERTY_U | PROPERTY_D,
            )),
            Fragment::True => Ok(TypeInfo::new(MINISCRIPT_TYPE_B, PROPERTY_Z | PROPERTY_U)),
            Fragment::PkK { key } => Ok(TypeInfo::new(
                MINISCRIPT_TYPE_K,
                PROPERTY_O | PROPERTY_N | PROPERTY_D | PROPERTY_U,
            )),
            Fragment::PkH { key } => Ok(TypeInfo::new(
                MINISCRIPT_TYPE_K,
                PROPERTY_N | PROPERTY_D | PROPERTY_U,
            )),
            // Fragment::Pk { key } => Ok(TypeInfo::new(MINISCRIPT_TYPE_K)),
            // Fragment::Pkh { key } => Ok(TypeInfo::new(MINISCRIPT_TYPE_K)),
            Fragment::Older { n } => Ok(TypeInfo::new(MINISCRIPT_TYPE_B, PROPERTY_Z)),
            Fragment::After { n } => Ok(TypeInfo::new(MINISCRIPT_TYPE_B, PROPERTY_Z)),
            Fragment::Sha256 { h } => Ok(TypeInfo::new(
                MINISCRIPT_TYPE_B,
                PROPERTY_O | PROPERTY_N | PROPERTY_D | PROPERTY_U,
            )),
            Fragment::Hash256 { h } => Ok(TypeInfo::new(
                MINISCRIPT_TYPE_B,
                PROPERTY_O | PROPERTY_N | PROPERTY_D | PROPERTY_U,
            )),
            Fragment::Ripemd160 { h } => Ok(TypeInfo::new(
                MINISCRIPT_TYPE_B,
                PROPERTY_O | PROPERTY_N | PROPERTY_D | PROPERTY_U,
            )),
            Fragment::Hash160 { h } => Ok(TypeInfo::new(
                MINISCRIPT_TYPE_B,
                PROPERTY_O | PROPERTY_N | PROPERTY_D | PROPERTY_U,
            )),

            Fragment::AndOr { x, y, z } => {
                // X is Bdu; Y and Z are both B, K, or V
                let x_type = self.visit_ast(&x)?;
                let y_type = self.visit_ast(&y)?;
                let z_type = self.visit_ast(&z)?;

                if x_type.base_type() != MINISCRIPT_TYPE_B {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "andor(X,Y,Z): X must be type B (Base), but got type {:?}",
                            x_type.base_type()
                        ),
                    });
                }

                if !x_type.has_properties(PROPERTY_D | PROPERTY_U) {
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

                if y_type.base_type() != MINISCRIPT_TYPE_B
                    && y_type.base_type() != MINISCRIPT_TYPE_K
                    && y_type.base_type() != MINISCRIPT_TYPE_V
                {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "andor(X,Y,Z): Y must be type B (Base), K (Key), or V (Verify), but got type {:?}",
                            y_type.base_type()
                        ),
                    });
                }

                // properties: z=zXzYzZ; o=zXoYoZ or oXzYzZ; u=uYuZ; d=dZ
                let mut properties = 0;

                if x_type.has_property(PROPERTY_Z)
                    && y_type.has_property(PROPERTY_Z)
                    && z_type.has_property(PROPERTY_Z)
                {
                    properties |= PROPERTY_Z;
                }
                if (x_type.has_property(PROPERTY_Z)
                    && y_type.has_property(PROPERTY_O)
                    && z_type.has_property(PROPERTY_O))
                    || (x_type.has_property(PROPERTY_O)
                        && y_type.has_property(PROPERTY_Z)
                        && z_type.has_property(PROPERTY_Z))
                {
                    properties |= PROPERTY_O;
                }
                if y_type.has_property(PROPERTY_U) && z_type.has_property(PROPERTY_U) {
                    properties |= PROPERTY_U;
                }
                if z_type.has_property(PROPERTY_D) {
                    properties |= PROPERTY_D;
                }

                Ok(TypeInfo::new(y_type.base_type(), properties))
            }
            Fragment::AndV { x, y } => {
                // X is V; Y is B, K, or V
                let x_type = self.visit_ast(&x)?;
                let y_type = self.visit_ast(&y)?;

                if x_type.base_type() != MINISCRIPT_TYPE_V {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "and_v(X,Y): X must be type V (Verify), but got type {:?}",
                            x_type.base_type()
                        ),
                    });
                }

                if y_type.base_type() != MINISCRIPT_TYPE_B
                    && y_type.base_type() != MINISCRIPT_TYPE_K
                    && y_type.base_type() != MINISCRIPT_TYPE_V
                {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "and_v(X,Y): Y must be type B (Base), K (Key), or V (Verify), but got type {:?}",
                            y_type.base_type()
                        ),
                    });
                }

                // properties: z=zXzY; o=zXoY or zYoX; n=nX or zXnY; u=uY
                let mut properties = 0;

                if x_type.has_property(PROPERTY_Z) && y_type.has_property(PROPERTY_Z) {
                    properties |= PROPERTY_Z;
                }
                if (x_type.has_property(PROPERTY_Z) && y_type.has_property(PROPERTY_O))
                    || (x_type.has_property(PROPERTY_O) && y_type.has_property(PROPERTY_Z))
                {
                    properties |= PROPERTY_O;
                }
                if y_type.has_property(PROPERTY_N)
                    || (x_type.has_property(PROPERTY_Z) && y_type.has_property(PROPERTY_N))
                {
                    properties |= PROPERTY_N;
                }
                if y_type.has_property(PROPERTY_U) {
                    properties |= PROPERTY_U;
                }

                Ok(TypeInfo::new(y_type.base_type(), properties))
            }
            Fragment::AndB { x, y } => {
                // X is B; Y is W
                let x_type = self.visit_ast(&x)?;
                let y_type = self.visit_ast(&y)?;

                if x_type.base_type() != MINISCRIPT_TYPE_B {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "and_b(X,Y): X must be type B (Base), but got type {:?}",
                            x_type.base_type()
                        ),
                    });
                }

                if y_type.base_type() != MINISCRIPT_TYPE_W {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "and_b(X,Y): Y must be type W (Wrapped), but got type {:?}",
                            y_type.base_type()
                        ),
                    });
                }

                // properties: z=zXzY; o=zXoY or zYoX; n=nX or zXnY; d=dXdY; u

                let mut properties = 0;

                if x_type.has_property(PROPERTY_Z) && y_type.has_property(PROPERTY_Z) {
                    properties |= PROPERTY_Z;
                }
                if (x_type.has_property(PROPERTY_Z) && y_type.has_property(PROPERTY_O))
                    || (x_type.has_property(PROPERTY_O) && y_type.has_property(PROPERTY_Z))
                {
                    properties |= PROPERTY_O;
                }
                if y_type.has_property(PROPERTY_N)
                    || (x_type.has_property(PROPERTY_Z) && y_type.has_property(PROPERTY_N))
                {
                    properties |= PROPERTY_N;
                }

                if x_type.has_property(PROPERTY_D) && y_type.has_property(PROPERTY_D) {
                    properties |= PROPERTY_D;
                }
                properties |= PROPERTY_U;

                Ok(TypeInfo::new(MINISCRIPT_TYPE_B, properties))
            }
            // Fragment::AndN { x, y } => Ok(TypeInfo::new(MINISCRIPT_TYPE_B)),
            Fragment::OrB { x, z } => {
                // X is Bd; Z is Wd
                let x_type = self.visit_ast(&x)?;
                let z_type = self.visit_ast(&z)?;

                if x_type.base_type() != MINISCRIPT_TYPE_B {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "or_b(X,Z): X must be type B (Base), but got type {:?}",
                            x_type.base_type()
                        ),
                    });
                }

                if !x_type.has_property(PROPERTY_D) {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "or_b(X,Z): X must have property D (Data), but got properties {:?}",
                            x_type.properties()
                        ),
                    });
                }

                if z_type.base_type() != MINISCRIPT_TYPE_W {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "or_b(X,Z): Z must be type W (Wrapped), but got type {:?}",
                            z_type.base_type()
                        ),
                    });
                }

                if !z_type.has_property(PROPERTY_D) {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "or_b(X,Z): Z must have property D (Data), but got properties {:?}",
                            z_type.properties()
                        ),
                    });
                }

                // properties: z=zXzZ; o=zXoZ or zZoX; d; u

                let mut properties = 0;

                if x_type.has_property(PROPERTY_Z) && z_type.has_property(PROPERTY_Z) {
                    properties |= PROPERTY_Z;
                }
                if (x_type.has_property(PROPERTY_Z) && z_type.has_property(PROPERTY_O))
                    || (x_type.has_property(PROPERTY_O) && z_type.has_property(PROPERTY_Z))
                {
                    properties |= PROPERTY_O;
                }
                properties |= PROPERTY_D;
                properties |= PROPERTY_U;

                Ok(TypeInfo::new(MINISCRIPT_TYPE_B, properties))
            }
            Fragment::OrC { x, z } => {
                // X is Bdu; Z is V
                let x_type = self.visit_ast(&x)?;
                let z_type = self.visit_ast(&z)?;

                if x_type.base_type() != MINISCRIPT_TYPE_B {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "or_c(X,Z): X must be type B (Base), but got type {:?}",
                            x_type.base_type()
                        ),
                    });
                }

                if !x_type.has_properties(PROPERTY_D | PROPERTY_U) {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "or_c(X,Z): X must have properties D (Data) and U (Unknown), but got properties {:?}",
                            x_type.properties()
                        ),
                    });
                }

                if z_type.base_type() != MINISCRIPT_TYPE_V {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "or_c(X,Z): Z must be type V (Verify), but got type {:?}",
                            z_type.base_type()
                        ),
                    });
                }

                // properties: z=zXzZ; o=oXzZ

                let mut properties = 0;

                if x_type.has_property(PROPERTY_Z) && z_type.has_property(PROPERTY_Z) {
                    properties |= PROPERTY_Z;
                }
                if x_type.has_property(PROPERTY_O) && z_type.has_property(PROPERTY_Z) {
                    properties |= PROPERTY_O;
                }
                Ok(TypeInfo::new(MINISCRIPT_TYPE_V, properties))
            }
            Fragment::OrD { x, z } => {
                // X is Bdu; Z is B
                let x_type = self.visit_ast(&x)?;
                let z_type = self.visit_ast(&z)?;

                if x_type.base_type() != MINISCRIPT_TYPE_B {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "or_d(X,Z): X must be type B (Base), but got type {:?}",
                            x_type.base_type()
                        ),
                    });
                }

                if !x_type.has_properties(PROPERTY_D | PROPERTY_U) {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "or_d(X,Z): X must have properties D (Data) and U (Unknown), but got properties {:?}",
                            x_type.properties()
                        ),
                    });
                }

                if z_type.base_type() != MINISCRIPT_TYPE_B {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "or_d(X,Z): Z must be type B (Base), but got type {:?}",
                            z_type.base_type()
                        ),
                    });
                }

                // properties: z=zXzZ; o=oXzZ; d=dZ; u=uZ

                let mut properties = 0;

                if x_type.has_property(PROPERTY_Z) && z_type.has_property(PROPERTY_Z) {
                    properties |= PROPERTY_Z;
                }
                if x_type.has_property(PROPERTY_O) && z_type.has_property(PROPERTY_Z) {
                    properties |= PROPERTY_O;
                }
                if z_type.has_property(PROPERTY_D) {
                    properties |= PROPERTY_D;
                }

                if z_type.has_property(PROPERTY_U) {
                    properties |= PROPERTY_U;
                }

                Ok(TypeInfo::new(MINISCRIPT_TYPE_B, properties))
            }
            Fragment::OrI { x, z } => {
                // both are B, K, or V
                let x_type = self.visit_ast(&x)?;
                let z_type = self.visit_ast(&z)?;

                if x_type.base_type() != z_type.base_type() {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "or_i(X,Z): X and Z must have the same type, but X is {:?} and Z is {:?}",
                            x_type.base_type(),
                            z_type.base_type()
                        ),
                    });
                }

                if x_type.base_type() != MINISCRIPT_TYPE_B
                    && x_type.base_type() != MINISCRIPT_TYPE_K
                    && x_type.base_type() != MINISCRIPT_TYPE_V
                {
                    return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                        reason: format!(
                            "or_i(X,Z): X must be type B (Base), K (Key), or V (Verify), but got type {:?}",
                            x_type.base_type()
                        ),
                    });
                }

                // properties: o=zXzZ; u=uXuZ; d=dX or dZ

                let mut properties = 0;

                if x_type.has_property(PROPERTY_Z) && z_type.has_property(PROPERTY_Z) {
                    properties |= PROPERTY_Z;
                }
                if x_type.has_property(PROPERTY_U) && z_type.has_property(PROPERTY_U) {
                    properties |= PROPERTY_U;
                }
                if x_type.has_property(PROPERTY_D) || z_type.has_property(PROPERTY_D) {
                    properties |= PROPERTY_D;
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
                    let x_type = self.visit_ast(&x)?;
                    if first_type {
                        first_type = false;

                        if x_type.base_type() != MINISCRIPT_TYPE_B {
                            return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                                reason: format!(
                                    "thresh(k,X1,...,Xn): X1 must be type B (Base), but got type {:?}",
                                    x_type.base_type()
                                ),
                            });
                        }

                        if !x_type.has_properties(PROPERTY_D | PROPERTY_U) {
                            return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                                reason: format!(
                                    "thresh(k,X1,...,Xn): X{} must have properties D (Data) and U (Unknown), but got properties {:?}",
                                    i,
                                    x_type.properties()
                                ),
                            });
                        }
                    } else {
                        if x_type.base_type() != MINISCRIPT_TYPE_W {
                            return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                                reason: format!(
                                    "thresh(k,X1,...,Xn): X{} must be type W (Wrapped), but got type {:?}",
                                    i,
                                    x_type.base_type()
                                ),
                            });
                        }

                        if !x_type.has_properties(PROPERTY_D | PROPERTY_U) {
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

                let mut properties = 0;

                let mut z_count = 0;
                let mut o_count = 0;
                for x in xs {
                    let x_type = self.visit_ast(&x)?;
                    if x_type.has_property(PROPERTY_Z) {
                        z_count += 1;
                    } else if x_type.has_property(PROPERTY_O) {
                        o_count += 1;
                    }
                }
                if z_count == xs.len() {
                    properties |= PROPERTY_Z;
                }
                if o_count == 1 && z_count == xs.len() - 1 {
                    properties |= PROPERTY_O;
                }
                properties |= PROPERTY_D;
                properties |= PROPERTY_U;
                Ok(TypeInfo::new(MINISCRIPT_TYPE_B, properties))
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
                    MINISCRIPT_TYPE_B,
                    PROPERTY_N | PROPERTY_D | PROPERTY_U,
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

                Ok(TypeInfo::new(MINISCRIPT_TYPE_B, PROPERTY_D | PROPERTY_U))
            }
            Fragment::Identity { identity_type, x } => {
                let x_type = self.visit_ast(&x)?;

                match identity_type {
                    IdentityType::A => {
                        // X is B
                        if x_type.base_type() != MINISCRIPT_TYPE_B {
                            return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                                reason: format!(
                                    "a:X: X must be type B (Base), but got type {:?}",
                                    x_type.base_type()
                                ),
                            });
                        }

                        // properties: d=dX; u=uX
                        let mut properties = 0;
                        if x_type.has_property(PROPERTY_D) {
                            properties |= PROPERTY_D;
                        }
                        if x_type.has_property(PROPERTY_U) {
                            properties |= PROPERTY_U;
                        }
                        Ok(TypeInfo::new(MINISCRIPT_TYPE_W, properties))
                    }
                    IdentityType::S => {
                        // X is Bo
                        if x_type.base_type() != MINISCRIPT_TYPE_B {
                            return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                                reason: format!(
                                    "s:X: X must be type B (Base), but got type {:?}",
                                    x_type.base_type()
                                ),
                            });
                        }

                        // properties: d=dX; u=uX
                        let mut properties = 0;
                        if x_type.has_property(PROPERTY_D) {
                            properties |= PROPERTY_D;
                        }
                        if x_type.has_property(PROPERTY_U) {
                            properties |= PROPERTY_U;
                        }
                        Ok(TypeInfo::new(MINISCRIPT_TYPE_W, properties))
                    }
                    IdentityType::C => {
                        // X is K
                        if x_type.base_type() != MINISCRIPT_TYPE_K {
                            return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                                reason: format!(
                                    "c:X: X must be type K (Key), but got type {:?}",
                                    x_type.base_type()
                                ),
                            });
                        }

                        // properties: o=oX; n=nX; d=dX; u
                        let mut properties = 0;
                        if x_type.has_property(PROPERTY_O) {
                            properties |= PROPERTY_O;
                        }
                        if x_type.has_property(PROPERTY_N) {
                            properties |= PROPERTY_N;
                        }
                        if x_type.has_property(PROPERTY_D) {
                            properties |= PROPERTY_D;
                        }
                        properties |= PROPERTY_U;
                        Ok(TypeInfo::new(MINISCRIPT_TYPE_B, properties))
                    }

                    IdentityType::D => {
                        // X is Vz
                        if x_type.base_type() != MINISCRIPT_TYPE_V {
                            return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                                reason: format!(
                                    "d:X: X must be type V (Verify), but got type {:?}",
                                    x_type.base_type()
                                ),
                            });
                        }

                        // properties: o; n; d; (Tapscript only) u
                        let mut properties = 0;
                        properties |= PROPERTY_O;
                        properties |= PROPERTY_N;
                        properties |= PROPERTY_D;
                        properties |= PROPERTY_U; // TODO: Tapscript only

                        Ok(TypeInfo::new(MINISCRIPT_TYPE_B, properties))
                    }

                    IdentityType::V => {
                        // X is B
                        if x_type.base_type() != MINISCRIPT_TYPE_B {
                            return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                                reason: format!(
                                    "v:X: X must be type B (Base), but got type {:?}",
                                    x_type.base_type()
                                ),
                            });
                        }

                        // properties: z=zX; o=oX; n=nX
                        let mut properties = 0;
                        if x_type.has_property(PROPERTY_Z) {
                            properties |= PROPERTY_Z;
                        }
                        if x_type.has_property(PROPERTY_O) {
                            properties |= PROPERTY_O;
                        }
                        if x_type.has_property(PROPERTY_N) {
                            properties |= PROPERTY_N;
                        }
                        Ok(TypeInfo::new(MINISCRIPT_TYPE_V, properties))
                    }

                    IdentityType::J => {
                        // X is Bn
                        if x_type.base_type() != MINISCRIPT_TYPE_B {
                            return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                                reason: format!(
                                    "j:X: X must be type B (Base), but got type {:?}",
                                    x_type.base_type()
                                ),
                            });
                        }

                        // properties: o=oX; n; d; u=uX

                        let mut properties = 0;
                        if x_type.has_property(PROPERTY_O) {
                            properties |= PROPERTY_O;
                        }
                        properties |= PROPERTY_N;
                        properties |= PROPERTY_D;
                        if x_type.has_property(PROPERTY_U) {
                            properties |= PROPERTY_U;
                        }
                        Ok(TypeInfo::new(MINISCRIPT_TYPE_B, properties))
                    }

                    IdentityType::N => {
                        // X is B
                        if x_type.base_type() != MINISCRIPT_TYPE_B {
                            return Err(CorrectnessPropertiesVisitorError::UnexpectedType {
                                reason: format!(
                                    "n:X: X must be type B (Base), but got type {:?}",
                                    x_type.base_type()
                                ),
                            });
                        }

                        // properties: z=zX; o=oX; n=nX; d=dX; u

                        let mut properties = 0;
                        if x_type.has_property(PROPERTY_Z) {
                            properties |= PROPERTY_Z;
                        }
                        if x_type.has_property(PROPERTY_O) {
                            properties |= PROPERTY_O;
                        }
                        if x_type.has_property(PROPERTY_N) {
                            properties |= PROPERTY_N;
                        }
                        if x_type.has_property(PROPERTY_D) {
                            properties |= PROPERTY_D;
                        }
                        properties |= PROPERTY_U;

                        Ok(TypeInfo::new(MINISCRIPT_TYPE_B, properties))
                    }
                }
            }
        }
    }
}
