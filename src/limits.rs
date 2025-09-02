use bitcoin::ScriptBuf;

use crate::{bitcoin_definition_link, descriptor::Descriptor};

/// Maximum script element size allowed by consensus rules.
#[doc = bitcoin_definition_link!("8333aa5302902f6be929c30b3c2b4e91c6583224", "script/script.h", 28)]
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

#[cfg_attr(feature = "debug", derive(Debug))]
pub enum LimitsError {
    ScriptTooLarge {
        size: usize,
        max_size: usize,
    },
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
