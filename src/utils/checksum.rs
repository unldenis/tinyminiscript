// Modified implementation from https://github.com/rust-bitcoin/rust-miniscript/blob/255b9d950ba04859bc16fb77567808a77b736071/src/descriptor/checksum.rs#L94

// SPDX-License-Identifier: CC0-1.0

//! Descriptor checksum
//!
//! This module contains a re-implementation of the function used by Bitcoin Core to calculate the
//! checksum of a descriptor. The checksum algorithm is specified in [BIP-380].
//!
//! [BIP-380]: <https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki>

use core::convert::TryFrom;
use core::{array, fmt};

use bech32::primitives::checksum::PackedFe32;
use bech32::{Checksum, Fe32};
use bitcoin::bech32;

const CHECKSUM_LENGTH: usize = 8;
const CODE_LENGTH: usize = 32767;

/// Map of valid characters in descriptor strings.
///
/// The map starts at 32 (space) and runs up to 126 (tilde).
#[rustfmt::skip]
const CHAR_MAP: [u8; 95] = [
    94, 59, 92, 91, 28, 29, 50, 15, 10, 11, 17, 51, 14, 52, 53, 16,
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 27, 54, 55, 56, 57, 58,
    26, 82, 83, 84, 85, 86, 87, 88, 89, 32, 33, 34, 35, 36, 37, 38,
    39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 12, 93, 13, 60, 61,
    90, 18, 19, 20, 21, 22, 23, 24, 25, 64, 65, 66, 67, 68, 69, 70,
    71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 30, 62, 31, 63,
];

/// Error validating descriptor checksum.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Character outside of descriptor charset.
    InvalidCharacter {
        /// The character in question.
        ch: char,
        /// Its position in the string.
        pos: usize,
    },
    /// Checksum had the incorrect length.
    InvalidChecksumLength {
        /// The length of the  checksum in the string.
        actual: usize,
        /// The length of a valid descriptor checksum.
        expected: usize,
    },
    /// Checksum was invalid.
    InvalidChecksum {
        /// The checksum in the string.
        actual: [char; CHECKSUM_LENGTH],
        /// The checksum that should have been there, assuming the string is valid.
        expected: [char; CHECKSUM_LENGTH],
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::InvalidCharacter { ch, pos } => {
                write!(f, "invalid character '{}' (position {})", ch, pos)
            }
            Error::InvalidChecksumLength { actual, expected } => {
                write!(
                    f,
                    "invalid checksum (length {}, expected {})",
                    actual, expected
                )
            }
            Error::InvalidChecksum { actual, expected } => {
                f.write_str("invalid checksum ")?;
                for ch in actual {
                    ch.fmt(f)?;
                }
                f.write_str("; expected ")?;
                for ch in expected {
                    ch.fmt(f)?;
                }
                Ok(())
            }
        }
    }
}

/// Helper function for `FromStr` for various descriptor types.
///
/// Checks and verifies the checksum if it is present and returns the descriptor
/// string without the checksum.
pub fn verify_checksum(s: &str) -> Result<&str, Error> {
    let mut last_hash_pos = s.len();
    for (pos, ch) in s.char_indices() {
        if !(32..127).contains(&u32::from(ch)) {
            return Err(Error::InvalidCharacter { ch, pos });
        } else if ch == '#' {
            last_hash_pos = pos;
        }
    }
    // After this point we know we have ASCII and can stop using character methods.

    if last_hash_pos < s.len() {
        let checksum_str = &s[last_hash_pos + 1..];
        if checksum_str.len() != CHECKSUM_LENGTH {
            return Err(Error::InvalidChecksumLength {
                actual: checksum_str.len(),
                expected: CHECKSUM_LENGTH,
            });
        }

        let mut eng = Engine::new();
        eng.input_unchecked(&s.as_bytes()[..last_hash_pos]);

        let expected = eng.checksum_chars();

        let mut iter = checksum_str.chars();
        let actual: [char; CHECKSUM_LENGTH] =
            array::from_fn(|_| iter.next().expect("length checked above"));

        if expected != actual {
            return Err(Error::InvalidChecksum { actual, expected });
        }
    }
    Ok(&s[..last_hash_pos])
}

/// An engine to compute a checksum from a string.
pub struct Engine {
    inner: bech32::primitives::checksum::Engine<DescriptorChecksum>,
    cls: u64,
    clscount: u64,
}

impl Default for Engine {
    fn default() -> Engine {
        Engine::new()
    }
}

impl Engine {
    /// Constructs an engine with no input.
    pub fn new() -> Self {
        Engine {
            inner: bech32::primitives::checksum::Engine::new(),
            cls: 0,
            clscount: 0,
        }
    }

    fn input_unchecked(&mut self, s: &[u8]) {
        for ch in s {
            let pos = u64::from(CHAR_MAP[usize::from(*ch) - 32]);
            let fe = Fe32::try_from(pos & 31).expect("pos is valid because of the mask");
            self.inner.input_fe(fe);

            self.cls = self.cls * 3 + (pos >> 5);
            self.clscount += 1;
            if self.clscount == 3 {
                let fe = Fe32::try_from(self.cls).expect("cls is valid");
                self.inner.input_fe(fe);
                self.cls = 0;
                self.clscount = 0;
            }
        }
    }

    /// Obtains the checksum characters of all the data thus-far fed to the
    /// engine without allocating, to get a string use [`Self::checksum`].
    pub fn checksum_chars(&mut self) -> [char; CHECKSUM_LENGTH] {
        if self.clscount > 0 {
            let fe = Fe32::try_from(self.cls).expect("cls is valid");
            self.inner.input_fe(fe);
        }
        self.inner.input_target_residue();

        let mut chars = [0 as char; CHECKSUM_LENGTH];
        let mut checksum_remaining = CHECKSUM_LENGTH;

        for checksum_ch in &mut chars {
            checksum_remaining -= 1;
            let unpacked = self.inner.residue().unpack(checksum_remaining);
            let fe = Fe32::try_from(unpacked).expect("5 bits fits in an fe32");
            *checksum_ch = fe.to_char();
        }
        chars
    }
}

/// The Output Script Descriptor checksum algorithm, defined in [BIP-380].
///
/// [BIP-380]: <https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki>
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum DescriptorChecksum {}

/// Generator coefficients, taken from BIP-380.
#[rustfmt::skip]
const GEN: [u64; 5] = [0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd];

impl Checksum for DescriptorChecksum {
    type MidstateRepr = u64; // We need 40 bits (8 * 5).
    const CHECKSUM_LENGTH: usize = CHECKSUM_LENGTH;
    const CODE_LENGTH: usize = CODE_LENGTH;
    const GENERATOR_SH: [u64; 5] = GEN;
    const TARGET_RESIDUE: u64 = 1;
}
