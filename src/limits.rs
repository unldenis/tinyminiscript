use bitcoin::ScriptBuf;

use crate::{bitcoin_definition_link, descriptor::Descriptor};

/// Maximum allowed absolute locktime value.
const MAX_ABSOLUTE_LOCKTIME: u32 = 0x7FFF_FFFF;

/// Minimum allowed absolute locktime value.
///
/// In Bitcoin 0 is an allowed value, but in Miniscript it is not, because we
/// (ab)use the locktime value as a boolean in our Script fragments, and avoiding
/// this would reduce efficiency.
const MIN_ABSOLUTE_LOCKTIME: u32 = 1;

/// Maximum recursion depth allowed by consensus rules.
const MAX_RECURSION_DEPTH: u32 = 402;

/// Maximum script element size allowed by consensus rules.
#[doc = bitcoin_definition_link!("8333aa5302902f6be929c30b3c2b4e91c6583224", "script/script.h", 28)]
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// Maximum script size allowed by consensus rules
#[doc = bitcoin_definition_link!("42b66a6b814bca130a9ccf0a3f747cf33d628232", "script/script.h", 32)]
pub const MAX_SCRIPT_SIZE: usize = 10_000;

/// Maximum script size allowed by standardness rules
#[doc = bitcoin_definition_link!("283a73d7eaea2907a6f7f800f529a0d6db53d7a6", "policy/policy.h", 44)]
pub const MAX_STANDARD_P2WSH_SCRIPT_SIZE: usize = 3600;

/// Check if the absolute locktime is within the allowed range.
pub fn check_absolute_locktime(locktime: u32) -> Result<(), u32> {
    if locktime < MIN_ABSOLUTE_LOCKTIME || locktime > MAX_ABSOLUTE_LOCKTIME {
        return Err(locktime);
    }
    Ok(())
}

// Limits for Miniscript

#[cfg_attr(feature = "debug", derive(Debug))]
pub enum LimitsError {
    ScriptTooLarge { size: usize, max_size: usize },
    MaxRecursiveDepthExceeded { depth: usize, max_depth: u32 },
}

pub fn check_recursion_depth(depth: usize) -> Result<(), LimitsError> {
    if depth as u32 > MAX_RECURSION_DEPTH {
        return Err(LimitsError::MaxRecursiveDepthExceeded {
            depth,
            max_depth: MAX_RECURSION_DEPTH,
        });
    }
    Ok(())
}

pub fn check_script_size(descriptor: &Descriptor, script_size: usize) -> Result<(), LimitsError> {
    match descriptor {
        Descriptor::Bare => {}
        Descriptor::Pkh => {}
        Descriptor::Sh => {
            if script_size > MAX_SCRIPT_ELEMENT_SIZE {
                return Err(LimitsError::ScriptTooLarge {
                    size: script_size,
                    max_size: MAX_SCRIPT_ELEMENT_SIZE,
                });
            }
        }
        Descriptor::Wpkh => {}
        Descriptor::Wsh => {
            if script_size > MAX_SCRIPT_SIZE {
                return Err(LimitsError::ScriptTooLarge {
                    size: script_size,
                    max_size: MAX_SCRIPT_SIZE,
                });
            }

            if script_size > MAX_STANDARD_P2WSH_SCRIPT_SIZE {
                return Err(LimitsError::ScriptTooLarge {
                    size: script_size,
                    max_size: MAX_STANDARD_P2WSH_SCRIPT_SIZE,
                });
            }
        }
        Descriptor::Tr => {}
    }
    Ok(())
}
