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
        Descriptor::Wsh => {}
        Descriptor::Tr => {}
    }
    Ok(())
}

