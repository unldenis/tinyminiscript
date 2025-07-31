use core::fmt::Debug;

use crate::lexer::{Identifier, Int, Position, Token};

#[derive(Debug)]
pub enum Fragment<'a> {
    // Basic Fragments
    /// 0
    False { position: Position },
    /// 1
    True { position: Position },

    // Key Fragments
    /// pk_k(key)
    Pk_k {
        position: Position,
        key: Identifier<'a>,
    },
    /// pk_h(key)
    Pk_h {
        position: Position,
        key: Identifier<'a>,
    },
    /// pk(key) = c:pk_k(key)
    Pk {
        position: Position,
        key: Identifier<'a>,
    },
    /// pkh(key) = c:pk_h(key)
    Pkh {
        position: Position,
        key: Identifier<'a>,
    },

    // Time fragments
    /// older(n)
    Older { position: Position, n: Int },
    /// after(n)
    After { position: Position, n: Int },

    // Logical Fragments
    /// andor(X,Y,Z)
    AndOr {
        position: Position,
        x: &'a Fragment<'a>,
        y: &'a Fragment<'a>,
        z: &'a Fragment<'a>,
    },
    /// and_v(X,Y)
    And_v {
        position: Position,
        x: &'a Fragment<'a>,
        y: &'a Fragment<'a>,
    },
    /// and_b(X,Y)
    And_b {
        position: Position,
        x: &'a Fragment<'a>,
        y: &'a Fragment<'a>,
    },
    /// and_n(X,Y) = andor(X,Y,0)
    And_n {
        position: Position,
        x: &'a Fragment<'a>,
        y: &'a Fragment<'a>,
    },
    /// or_b(X,Z)
    Or_b {
        position: Position,
        x: &'a Fragment<'a>,
        z: &'a Fragment<'a>,
    },
    /// or_c(X,Z)
    Or_c {
        position: Position,
        x: &'a Fragment<'a>,
        z: &'a Fragment<'a>,
    },
    /// or_d(X,Z)
    Or_d {
        position: Position,
        x: &'a Fragment<'a>,
        z: &'a Fragment<'a>,
    },
    /// or_i(X,Z)
    Or_i {
        position: Position,
        x: &'a Fragment<'a>,
        z: &'a Fragment<'a>,
    },

    // Threshold Fragments
    /// thresh(k,X1,...,Xn)
    Thresh {
        position: Position,
        k: Int,
        xs: [&'a Fragment<'a>; 16],
    },
    ///  multi(k,key1,...,keyn)
    /// (P2WSH only)
    Multi {
        position: Position,
        k: Int,
        keys: [&'a Identifier<'a>; 16],
    },
    /// multi_a(k,key1,...,keyn)
    /// (Tapscript only)
    Multi_a {
        position: Position,
        k: Int,
        keys: [&'a Identifier<'a>; 16],
    },
}
