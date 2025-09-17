use core::ops::Deref;

use bitcoin::Witness;

use crate::{
    bitcoin_definition_link, parser::{keys::KeyToken, Fragment, ParserContext, AST}, Vec
};

use alloc::string::String;

pub trait Satisfier {
    /// CheckOlder checks if the OP_CHECKSEQUENCEVERIFY call is satisfied in the context of a
    /// transaction.
    fn check_older(&self, locktime: u32) -> Option<bool>;

    /// CheckAfter checks if the OP_CHECKLOCKTIMEVERIFY call is satisfied in the context of a
    /// transaction.
    fn check_after(&self, locktime: u32) -> Option<bool>;

    /// Sign generates a signature for the given public key.
    fn sign(&self, pubkey: &KeyToken) -> Option<(Vec<u8>, bool)>;

    /// Preimage returns the preimage of the hash value. hashFunc is one of "sha256", "ripemd160",
    /// "hash256", "hash160".
    fn preimage(&self, hash_func: HashFunc, hash: &[u8]) -> Option<(Vec<u8>, bool)>;
}

#[cfg_attr(feature = "debug", derive(Debug))]
#[repr(u8)]
pub enum HashFunc {
    Sha256,
    Ripemd160,
    Hash256,
    Hash160,
}

impl HashFunc {
    pub const fn expected_length(&self) -> usize {
        // match self {
        //     HashFunc::Sha256 | HashFunc::Hash256 => 32,
        //     HashFunc::Ripemd160 | HashFunc::Hash160 => 20,
        // }
        32
    }
}

/// Satisfaction is a struct that represents a satisfaction of a miniscript expression.
#[doc = bitcoin_definition_link!("8333aa5302902f6be929c30b3c2b4e91c6583224", "script/miniscript.h", 294)]
#[derive(Clone)]
#[cfg_attr(feature = "debug", derive(Debug))]
pub struct Satisfaction {
    pub witness: Witness,
    pub available: bool,
    pub malleable: bool,
    pub has_sig: bool,
}

impl Satisfaction {
    pub fn new(data: &[u8], available: bool, malleable: bool, has_sig: bool) -> Self {
        let mut witness = Witness::new();
        witness.push(data);
        Self {
            witness,
            available,
            malleable,
            has_sig,
        }
    }

    pub fn set_available(mut self, available: bool) -> Self {
        self.available = available;
        self
    }

    pub fn with_sig(mut self) -> Self {
        self.has_sig = true;
        self
    }

    pub fn set_malleable(mut self, malleable: bool) -> Self {
        self.malleable = malleable;
        self
    }

    pub fn and(&self, other: &Self) -> Self {
        Self {
            witness: Witness::from_slice(
                self.witness
                    .into_iter()
                    .chain(other.witness.into_iter())
                    .collect::<Vec<_>>()
                    .as_slice(),
            ),
            available: self.available && other.available,
            malleable: self.malleable || other.malleable,
            has_sig: self.has_sig || other.has_sig,
        }
    }

    pub fn or(&self, other: &Self) -> Self {
        let mut _self = self.clone();
        let mut _other = other.clone();

        // If only one (or neither) is valid, pick the other one.
        if !_self.available {
            return _other;
        }
        if !_other.available {
            return _self;
        }
        // If only one of the solutions has a signature, we must pick the other one.
        if !_self.has_sig && _other.has_sig {
            return _self;
        }
        if _self.has_sig && !_other.has_sig {
            return _other;
        }
        // If neither solution requires a signature, the result is inevitably malleable.
        if !_self.has_sig && !_other.has_sig {
            _self.malleable = true;
            _other.malleable = true;
        } else {
            // If both options require a signature, prefer the non-malleable one.
            if _other.malleable && !_self.malleable {
                return _self;
            }
            if _self.malleable && !_other.malleable {
                return _other;
            }
        }
        // Both avaiable, pick smaller one.
        if _self.available && _other.available {
            if _self.witness.size() <= _other.witness.size() {
                return _self;
            }
            return _other;
        }
        // If only one available, return that one. If both unavailable, the result is unavailable.
        if _self.available {
            return _self;
        }
        return _other;
    }
}

#[cfg_attr(feature = "debug", derive(Debug))]

pub struct Satisfactions {
    pub dsat: Satisfaction,
    pub sat: Satisfaction,
}

impl Satisfactions {
    #[inline]
    pub const fn new(dsat: Satisfaction, sat: Satisfaction) -> Self {
        Self { dsat, sat }
    }
}

#[cfg_attr(feature = "debug", derive(Debug))]
pub enum SatisfyError {
    MissingSignature(String),
    MissingLockTime(u32),
    MissingPreimage(HashFunc),
    InvalidPreimage(HashFunc),
    NonDefiniteKey(String),
    TaprootNotSupported,
}

const EMPTY: Satisfaction = Satisfaction {
    witness: Witness::new(),
    available: true,
    malleable: false,
    has_sig: false,
};

const UNAVAILABLE: Satisfaction = Satisfaction {
    witness: Witness::new(),
    available: false,
    malleable: false,
    has_sig: false,
};

/// Satisfy is a function that satisfies a miniscript expression.
#[doc = bitcoin_definition_link!("8333aa5302902f6be929c30b3c2b4e91c6583224", "script/miniscript.h", 1186)]
pub(crate) fn satisfy<'a>(
    ctx: &ParserContext<'a>,
    satisfier: &dyn Satisfier,
    node: &AST,
) -> Result<Satisfactions, SatisfyError> {
    let zero = || Satisfaction::new(&[], true, false, false);
    let one = || Satisfaction::new(&[1], true, false, false);
    let witness = |w: &[u8]| Satisfaction::new(w, true, false, false);

    match &node.fragment {
        Fragment::False => Ok(Satisfactions::new(EMPTY, UNAVAILABLE)),
        Fragment::True => Ok(Satisfactions::new(UNAVAILABLE, EMPTY)),
        Fragment::PkK { key } => {
                        let (sig, avail) = satisfier
                            .sign(key)
                            .ok_or(SatisfyError::MissingSignature(key.identifier()))?;
                        Ok(Satisfactions::new(
                            zero(),
                            witness(sig.as_slice()).with_sig().set_available(avail),
                        ))
            }
        Fragment::PkH { key } => {
                let (sig, avail) = satisfier
                    .sign(key)
                    .ok_or(SatisfyError::MissingSignature(key.identifier()))?;

                let key = match key.as_definite_key() {
                    Some(k) => k,
                    None => return Err(SatisfyError::NonDefiniteKey(key.identifier())),
                };

                Ok(Satisfactions::new(
                    zero().and(&witness(&key.to_bytes())),
                    witness(sig.as_slice())
                        .set_available(avail)
                        .and(&witness(&key.to_bytes())),
                ))
            }
        Fragment::Older { n } => {
                let avail = satisfier
                    .check_older(*n)
                    .ok_or(SatisfyError::MissingLockTime(*n))?;

                if avail {
                    Ok(Satisfactions::new(UNAVAILABLE, EMPTY))
                } else {
                    Ok(Satisfactions::new(UNAVAILABLE, UNAVAILABLE))
                }
            }
        Fragment::After { n } => {
                let avail = satisfier
                    .check_after(*n)
                    .ok_or(SatisfyError::MissingLockTime(*n))?;

                if avail {
                    Ok(Satisfactions::new(UNAVAILABLE, EMPTY))
                } else {
                    Ok(Satisfactions::new(UNAVAILABLE, UNAVAILABLE))
                }
            }
        Fragment::Sha256 { h } => {
                let (preimage, avail) = satisfier
                    .preimage(HashFunc::Sha256, h.as_slice())
                    .ok_or(SatisfyError::MissingPreimage(HashFunc::Sha256))?;

                if avail && preimage.len() != HashFunc::Sha256.expected_length() {
                    return Err(SatisfyError::InvalidPreimage(HashFunc::Sha256));
                }
                Ok(Satisfactions::new(
                    witness(&[0; HashFunc::Sha256.expected_length()]).set_malleable(true),
                    witness(preimage.as_slice()).set_available(avail),
                ))
            }
        Fragment::Hash256 { h } => {
                let (preimage, avail) = satisfier
                    .preimage(HashFunc::Hash256, h.as_slice())
                    .ok_or(SatisfyError::MissingPreimage(HashFunc::Hash256))?;
                if avail && preimage.len() != HashFunc::Hash256.expected_length() {
                    return Err(SatisfyError::InvalidPreimage(HashFunc::Hash256));
                }
                Ok(Satisfactions::new(
                    witness(&[0; HashFunc::Hash256.expected_length()]).set_malleable(true),
                    witness(preimage.as_slice()).set_available(avail),
                ))
            }
        Fragment::Ripemd160 { h } => {
                let (preimage, avail) = satisfier
                    .preimage(HashFunc::Ripemd160, h.as_slice())
                    .ok_or(SatisfyError::MissingPreimage(HashFunc::Ripemd160))?;
                if avail && preimage.len() != HashFunc::Ripemd160.expected_length() {
                    return Err(SatisfyError::InvalidPreimage(HashFunc::Ripemd160));
                }
                Ok(Satisfactions::new(
                    witness(&[0; HashFunc::Ripemd160.expected_length()]).set_malleable(true),
                    witness(preimage.as_slice()).set_available(avail),
                ))
            }
        Fragment::Hash160 { h } => {
                let (preimage, avail) = satisfier
                    .preimage(HashFunc::Hash160, h.as_slice())
                    .ok_or(SatisfyError::MissingPreimage(HashFunc::Hash160))?;
                if avail && preimage.len() != HashFunc::Hash160.expected_length() {
                    return Err(SatisfyError::InvalidPreimage(HashFunc::Hash160));
                }
                Ok(Satisfactions::new(
                    witness(&[0; HashFunc::Hash160.expected_length()]).set_malleable(true),
                    witness(preimage.as_slice()).set_available(avail),
                ))
            }
        Fragment::AndOr { x, y, z } => {
                let x = satisfy(ctx, satisfier, &ctx.get_node(*x))?;
                let y = satisfy(ctx, satisfier, &ctx.get_node(*y))?;
                let z = satisfy(ctx, satisfier, &ctx.get_node(*z))?;
                Ok(Satisfactions::new(
                    z.dsat.and(&x.dsat).or(&y.dsat.and(&x.sat)),
                    y.sat.and(&x.sat).or(&z.sat.and(&x.dsat)),
                ))
            }
        Fragment::AndV { x, y } => {
                let x = satisfy(ctx, satisfier, &ctx.get_node(*x))?;
                let y = satisfy(ctx, satisfier, &ctx.get_node(*y))?;
                Ok(Satisfactions::new(y.dsat.and(&x.sat), y.sat.and(&x.sat)))
            }
        Fragment::AndB { x, y } => {
                let x = satisfy(ctx, satisfier, &ctx.get_node(*x))?;
                let y = satisfy(ctx, satisfier, &ctx.get_node(*y))?;
                Ok(Satisfactions::new(
                    y.dsat
                        .and(&x.dsat)
                        .or(&y.sat.and(&x.dsat).set_malleable(true))
                        .or(&y.dsat.and(&x.sat).set_malleable(true)),
                    y.sat.and(&x.sat),
                ))
            }
        Fragment::OrB { x, z } => {
                let x = satisfy(ctx, satisfier, &ctx.get_node(*x))?;
                let z = satisfy(ctx, satisfier, &ctx.get_node(*z))?;
                Ok(Satisfactions::new(
                    z.dsat.and(&x.dsat),
                    z.dsat
                        .and(&x.sat)
                        .or(&z.sat.and(&x.dsat))
                        .or(&z.sat.and(&x.sat).set_malleable(true)),
                ))
            }
        Fragment::OrC { x, z } => {
                let x = satisfy(ctx, satisfier, &ctx.get_node(*x))?;
                let z = satisfy(ctx, satisfier, &ctx.get_node(*z))?;
                Ok(Satisfactions::new(
                    UNAVAILABLE,
                    x.sat.or(&z.sat.and(&x.dsat)),
                ))
            }
        Fragment::OrD { x, z } => {
                let x = satisfy(ctx, satisfier, &ctx.get_node(*x))?;
                let z = satisfy(ctx, satisfier, &ctx.get_node(*z))?;
                Ok(Satisfactions::new(
                    z.dsat.and(&x.dsat),
                    x.sat.or(&z.sat.and(&x.dsat)),
                ))
            }
        Fragment::OrI { x, z } => {
                let x = satisfy(ctx, satisfier, &ctx.get_node(*x))?;
                let z = satisfy(ctx, satisfier, &ctx.get_node(*z))?;
                Ok(Satisfactions::new(
                    x.dsat.and(&one()).or(&z.dsat.and(&zero())),
                    x.sat.and(&one()).or(&z.sat.and(&zero())),
                ))
            }
        Fragment::Thresh { k, xs } => {
                let n = xs.len();
                let mut sub_sats = Vec::new();
                for arg in xs {
                    let sat = satisfy(ctx, satisfier, &ctx.get_node(*arg))?;
                    sub_sats.push(sat);
                }

                // sats[k] represents the best stack that satisfies k out of the *last* i subexpressions.
                // In the loop below, these stacks are built up using a dynamic programming approach.
                // sats[0] starts off empty.
                let mut sats = Vec::new();
                sats.push(EMPTY);

                for i in 0..n {
                    // Introduce an alias for the i'th last satisfaction/dissatisfaction.
                    let res = &sub_sats[n - i - 1];

                    // Compute the next sats vector: next_sats[0] is sats[0] plus res.nsat (thus containing all dissatisfactions
                    // so far. next_sats[j] is either sats[j] + res.nsat (reusing j earlier satisfactions) or sats[j-1] + res.sat
                    // (reusing j-1 earlier satisfactions plus a new one). The very last next_sats[j] is all satisfactions.
                    let mut next_sats = Vec::new();
                    next_sats.push(sats[0].and(&res.dsat));

                    for j in 1..sats.len() {
                        next_sats.push((sats[j].and(&res.dsat)).or(&sats[j - 1].and(&res.sat)));
                    }
                    next_sats.push(sats[sats.len() - 1].and(&res.sat));

                    // Switch over.
                    sats = next_sats;
                }

                // At this point, sats[k].sat is the best satisfaction for the overall thresh() node. The best dissatisfaction
                // is computed by gathering all sats[i].nsat for i != k.
                let mut nsat = EMPTY.set_available(false);
                for i in 0..sats.len() {
                    // i==k is the satisfaction; i==0 is the canonical dissatisfaction;
                    // the rest are non-canonical (a no-signature dissatisfaction - the i=0
                    // form - is always available) and malleable (due to overcompleteness).
                    // Marking the solutions malleable here is not strictly necessary, as they
                    // should already never be picked in non-malleable solutions due to the
                    // availability of the i=0 form.
                    if i != 0 && i != *k as usize {
                        sats[i] = sats[i].clone().set_malleable(true);
                    }
                    // Include all dissatisfactions (even these non-canonical ones) in nsat.
                    if i != *k as usize {
                        nsat = nsat.or(&sats[i]);
                    }
                }

                // Safety check: k should be valid
                if *k as usize >= sats.len() {
                    return Err(SatisfyError::MissingLockTime(*k as u32));
                }

                Ok(Satisfactions::new(nsat, sats[*k as usize].clone()))
            }
        Fragment::Multi { k, keys } => {
                // sats[j] represents the best stack containing j valid signatures (out of the first i keys).
                // In the loop below, these stacks are built up using a dynamic programming approach.
                // sats[0] starts off being {0}, due to the CHECKMULTISIG bug that pops off one element too many.
                let mut sats = Vec::new();
                sats.push(zero());

                for i in 0..keys.len() {
                    let (sig, avail) = satisfier
                        .sign(&keys[i])
                        .ok_or(SatisfyError::MissingSignature(keys[i].identifier()))?;

                    // Compute signature stack for just the i'th key.
                    let sat = witness(&sig).with_sig().set_available(avail);

                    // Compute the next sats vector: next_sats[0] is a copy of sats[0] (no signatures). All further
                    // next_sats[j] are equal to either the existing sats[j], or sats[j-1] plus a signature for the
                    // current (i'th) key. The very last element needs all signatures filled.
                    let mut next_sats = Vec::new();
                    next_sats.push(sats[0].clone());

                    for j in 1..sats.len() {
                        next_sats.push(sats[j].or(&sats[j - 1].and(&sat)));
                    }
                    next_sats.push(sats[sats.len() - 1].and(&sat));

                    // Switch over.
                    sats = next_sats;
                }

                // The dissatisfaction consists of k+1 stack elements all equal to 0.
                let mut nsat = zero();
                for _ in 0..*k {
                    nsat = nsat.and(&zero());
                }

                // Safety check: k should be valid
                if *k as usize >= sats.len() {
                    return Err(SatisfyError::MissingLockTime(*k as u32));
                }

                Ok(Satisfactions::new(nsat, sats[*k as usize].clone()))
            }
        Fragment::Identity { identity_type, x } => {
                let x_pair = satisfy(ctx, satisfier, &ctx.get_node(*x))?;
                match identity_type {
                    crate::parser::IdentityType::D => {
                        Ok(Satisfactions::new(zero(), x_pair.sat.and(&one())))
                    }
                    crate::parser::IdentityType::V => Ok(Satisfactions::new(UNAVAILABLE, x_pair.sat)),
                    crate::parser::IdentityType::J => Ok(Satisfactions::new(
                        zero().set_malleable(x_pair.dsat.available && !x_pair.dsat.has_sig),
                        x_pair.sat,
                    )),
                    _ => return satisfy(ctx, satisfier, &ctx.get_node(*x)),
                }
            }
        Fragment::MultiA { k, keys } => {
                let n = keys.len();
                // sats[j] represents the best stack containing j valid signatures (out of the first i keys).
                // In the loop below, these stacks are built up using a dynamic programming approach.
                let mut sats = Vec::new();
                sats.push(EMPTY);

                for i in 0..n {
                    // Get the signature for the i'th key in reverse order (the signature for the first key needs to
                    // be at the top of the stack, contrary to CHECKMULTISIG's satisfaction).
                    let key_idx = n - 1 - i;
                    let key_type = &keys[key_idx];
                    let (sig, avail) = satisfier
                        .sign(&key_type)
                        .ok_or(SatisfyError::MissingSignature(key_type.identifier()))?;

                    // Compute signature stack for just this key.
                    let sat = witness(&sig).with_sig().set_available(avail);

                    // Compute the next sats vector: next_sats[0] is a copy of sats[0] (no signatures). All further
                    // next_sats[j] are equal to either the existing sats[j] + ZERO, or sats[j-1] plus a signature
                    // for the current (i'th) key. The very last element needs all signatures filled.
                    let mut next_sats = Vec::new();
                    next_sats.push(sats[0].and(&zero()));

                    for j in 1..sats.len() {
                        next_sats.push((sats[j].and(&zero())).or(&sats[j - 1].and(&sat)));
                    }
                    next_sats.push(sats[sats.len() - 1].and(&sat));

                    // Switch over.
                    sats = next_sats;
                }

                // The dissatisfaction consists of as many empty vectors as there are keys, which is the same as
                // satisfying 0 keys.
                let nsat = sats[0].clone();

                // Safety check: k should be valid
                if *k <= 0 || *k as usize >= sats.len() {
                    return Err(SatisfyError::MissingSignature(keys[0].identifier()));
                }

                Ok(Satisfactions::new(nsat, sats[*k as usize].clone()))
            }
        Fragment::Descriptor { descriptor, inner } => {
                satisfy(ctx, satisfier, &ctx.get_node(*inner))
            }
        Fragment::RawPkH { key } => {
                let (sig, avail) = satisfier
                    .sign(key)
                    .ok_or(SatisfyError::MissingSignature(key.identifier()))?;

                let key = match key.as_definite_key() {
                    Some(k) => k,
                    None => return Err(SatisfyError::NonDefiniteKey(key.identifier())),
                };

                Ok(Satisfactions::new(
                    zero().and(&witness(&key.to_bytes())),
                    witness(sig.as_slice())
                        .set_available(avail)
                        .and(&witness(&key.to_bytes())),
                ))
            }
        Fragment::RawTr { key, inner } => {
            return Err(SatisfyError::TaprootNotSupported);
        },
    }
}
