use core::ops::Deref;
use core::str::FromStr;

use alloc::{string::String, vec::Vec};
use bitcoin::bip32;
use bitcoin::hashes::Hash;
use bitcoin::{PubkeyHash, script::Builder, secp256k1};

use alloc::boxed::Box;
use alloc::rc::Rc;

use crate::descriptor::Descriptor;
use crate::parser::{ParseError, Position};

#[derive(Clone)]
/// A token for a public key.
pub struct KeyToken {
    pub inner: Rc<Box<dyn PublicKeyTrait>>,
}

impl KeyToken {
    pub fn as_extended_key<'a>(&'a self) -> Option<&'a ExtendedKey> {
        let s = self as &'a dyn core::any::Any;
        s.downcast_ref::<ExtendedKey>()
    }
}

#[cfg(feature = "debug")]
impl core::fmt::Debug for KeyToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.inner.identifier())
    }
}

impl Deref for KeyToken {
    type Target = Box<dyn PublicKeyTrait>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[cfg(feature = "debug")]
pub trait PublicKeyTrait: core::fmt::Debug {
    fn is_compressed(&self) -> bool;
    fn identifier(&self) -> String;
    fn as_definite_key(&self) -> Option<&dyn DefiniteKeyTrait>;
    fn derive(&self, index: u32) -> Result<Box<dyn DefiniteKeyTrait>, String>;
}
#[cfg(not(feature = "debug"))]
pub trait PublicKeyTrait {
    fn is_compressed(&self) -> bool;
    fn identifier(&self) -> String;
    fn as_definite_key(&self) -> Option<&dyn DefiniteKeyTrait>;
    fn derive(&self, index: u32) -> Result<Box<dyn DefiniteKeyTrait>, String>;
}

pub trait DefiniteKeyTrait: PublicKeyTrait {
    fn to_bytes(&self) -> Vec<u8>;
    fn push_to_script(&self, builder: Builder) -> Builder;
    fn pubkey_hash(&self) -> PubkeyHash;
}

impl PublicKeyTrait for bitcoin::PublicKey {
    fn is_compressed(&self) -> bool {
        self.compressed
    }
    fn identifier(&self) -> String {
        use alloc::string::ToString;
        self.to_string()
    }
    fn as_definite_key(&self) -> Option<&dyn DefiniteKeyTrait> {
        Some(self)
    }
    fn derive(&self, _: u32) -> Result<Box<dyn DefiniteKeyTrait>, String> {
        Ok(Box::new(self.clone()))
    }
}

impl DefiniteKeyTrait for bitcoin::PublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        bitcoin::PublicKey::to_bytes(*self)
    }
    fn push_to_script(&self, builder: Builder) -> Builder {
        builder.push_key(self)
    }
    fn pubkey_hash(&self) -> PubkeyHash {
        self.pubkey_hash()
    }
}

impl PublicKeyTrait for bitcoin::XOnlyPublicKey {
    fn is_compressed(&self) -> bool {
        true
    }
    fn identifier(&self) -> String {
        use alloc::string::ToString;
        self.to_string()
    }
    fn as_definite_key(&self) -> Option<&dyn DefiniteKeyTrait> {
        Some(self)
    }
    fn derive(&self, _: u32) -> Result<Box<dyn DefiniteKeyTrait>, String> {
        Ok(Box::new(self.clone()))
    }
}

impl DefiniteKeyTrait for bitcoin::XOnlyPublicKey {
    fn to_bytes(&self) -> Vec<u8> {
        self.serialize().to_vec()
    }
    fn push_to_script(&self, builder: Builder) -> Builder {
        builder.push_x_only_key(self)
    }
    fn pubkey_hash(&self) -> PubkeyHash {
        PubkeyHash::hash(&self.serialize().to_vec())
    }
}

#[cfg_attr(feature = "debug", derive(Debug))]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Wildcard {
    None,
    Normal,
}

impl core::fmt::Display for Wildcard {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Wildcard::None => write!(f, ""),
            Wildcard::Normal => write!(f, "/*"),
        }
    }
}

#[cfg_attr(feature = "debug", derive(Debug))]
#[derive(Clone)]
pub struct ExtendedKey {
    pub raw: String,
    pub origin: Option<(bip32::Fingerprint, bip32::DerivationPath)>,
    pub key: bip32::Xpub,
    pub path: bip32::DerivationPath,
    pub wildcard: Wildcard,
    pub x_only: bool,
}

impl PublicKeyTrait for ExtendedKey {
    fn is_compressed(&self) -> bool {
        true
    }
    fn identifier(&self) -> String {
        self.raw.clone()
    }
    fn as_definite_key(&self) -> Option<&dyn DefiniteKeyTrait> {
        None
    }
    fn derive(&self, index: u32) -> Result<Box<dyn DefiniteKeyTrait>, String> {
        let secp = secp256k1::Secp256k1::new();

        let mut path = self.path.clone();
        if let Wildcard::Normal = self.wildcard {
            path = path.child(
                bip32::ChildNumber::from_normal_idx(index)
                    .map_err(|e| alloc::format!("{:?}", e))?,
            );
        }

        let pubkey = self
            .key
            .derive_pub(&secp, &path)
            .map_err(|e| alloc::format!("{:?}", e))?;

        if self.x_only {
            Ok(Box::new(bitcoin::XOnlyPublicKey::from(pubkey.public_key)))
        } else {
            Ok(Box::new(bitcoin::PublicKey::from(pubkey.public_key)))
        }
    }
}

impl core::fmt::Display for ExtendedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use alloc::string::ToString;

        if let Some((fingerprint, path)) = &self.origin {
            write!(f, "[{fingerprint}{}{}]", if path.is_empty() { "" } else { "/" }, &path.to_string() )?;
        }

        write!(f, "{}", self.key)?;
        write!(f, "{}{}", if self.path.is_empty() { "" } else { "/" }, &self.path.to_string())?;
        write!(f, "{}", self.wildcard)?;

        Ok(())
    }
}

pub fn parse_key<'a>(
    token: (&'a str, Position),
    descriptor: &Descriptor,
) -> Result<KeyToken, ParseError<'a>> {
    // Try parsing as extended key first
    if token.0.contains("pub") {
        // Format: [fingerprint/path]xpub.../path or just xpub.../path
        let mut origin_fingerprint = None;
        let mut origin_path = None;
        let mut remaining = token.0;

        // Check if we have an origin part
        remaining = if token.0.starts_with('[') {
            let parts: Vec<&str> = token.0.splitn(2, ']').collect();
            if parts.len() != 2 {
                return Err(ParseError::InvalidKey {
                    key: token.0,
                    position: token.1,
                    inner: "Invalid format: missing closing square bracket",
                });
            }

            // Extract origin part [fingerprint/path]
            let origin_part = &parts[0][1..]; // Remove the leading '['
            if origin_part.len() < 9 {
                return Err(ParseError::InvalidKey {
                    key: token.0,
                    position: token.1,
                    inner: "Invalid origin format",
                });
            }

            // Parse fingerprint
            let fingerprint_part = &origin_part[..8];
            origin_fingerprint =
                Some(bip32::Fingerprint::from_str(fingerprint_part).map_err(|_| {
                    ParseError::InvalidKey {
                        key: token.0,
                        position: token.1,
                        inner: "Invalid origin fingerprint",
                    }
                })?);

            let remaining = &origin_part[8..];
            if !remaining.is_empty() {
                // Parse origin path
                let origin_path_str = alloc::format!("m{}", &remaining[..(remaining.len() - 1)]);
                origin_path = Some(bip32::DerivationPath::from_str(&origin_path_str).map_err(
                    |_| ParseError::InvalidKey {
                        key: token.0,
                        position: token.1,
                        inner: "Invalid origin path",
                    },
                )?);
            }

            parts[1]
        } else {
            token.0
        };

        let mut wildcard = Wildcard::None;
        let x_only = *descriptor == Descriptor::Tr;

        let parts = remaining.splitn(2, '/').collect::<Vec<&str>>();
        let key_part = parts[0];
        let suffix = parts.get(1);
        let path_str = suffix
            .map(|suffix| {
                let mut path_str = alloc::format!("m/{}", suffix);

                // Check for wildcard
                if path_str.ends_with("/*") {
                    wildcard = Wildcard::Normal;
                    path_str = path_str[..path_str.len() - 2].into();
                } else if path_str.ends_with("/*'") {
                    return Err(ParseError::InvalidKey {
                        key: token.0,
                        position: token.1,
                        inner: "Invalid format: hardened wildcard not allowed",
                    });
                }

                Ok(path_str)
            })
            .transpose()?;

        // Parse the key
        let key = bip32::Xpub::from_str(key_part).map_err(|_| ParseError::InvalidKey {
            key: token.0,
            position: token.1,
            inner: "Invalid xpub",
        })?;

        // Parse the path
        let path = match path_str {
            Some(path_str) => {
                bip32::DerivationPath::from_str(&path_str).map_err(|_| ParseError::InvalidKey {
                    key: token.0,
                    position: token.1,
                    inner: "Invalid path",
                })?
            }
            None => Default::default(),
        };

        let key = Box::new(ExtendedKey {
            raw: token.0.into(),
            origin: match (origin_fingerprint, origin_path) {
                (Some(fingerprint), Some(path)) => Some((fingerprint, path)),
                (Some(fingerprint), None) => Some((fingerprint, Default::default())),
                _ => None,
            },
            key,
            path,
            wildcard,
            x_only,
        });
        return Ok(KeyToken {
            inner: Rc::new(key),
        });
    }

    // Get the key type based on the inner descriptor
    let key = match descriptor {
        Descriptor::Tr => Box::new(bitcoin::XOnlyPublicKey::from_str(token.0).map_err(|_| {
            ParseError::InvalidXOnlyKey {
                key: token.0,
                position: token.1,
            }
        })?) as Box<dyn PublicKeyTrait>,
        _ => {
            Box::new(
                bitcoin::PublicKey::from_str(token.0).map_err(|e| ParseError::InvalidKey {
                    key: token.0,
                    position: token.1,
                    inner: "Invalid bitcoin::PublicKey key",
                })?,
            ) as Box<dyn PublicKeyTrait>
        }
    };
    Ok(KeyToken {
        inner: Rc::new(key),
    })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_key() {
        let key = "[aabbccdd/10'/123]tpubDAenfwNu5GyCJWv8oqRAckdKMSUoZjgVF5p8WvQwHQeXjDhAHmGrPa4a4y2Fn7HF2nfCLefJanHV3ny1UY25MRVogizB2zRUdAo7Tr9XAjm/10/*";
        let key = parse_key((key, 0), &Descriptor::Wpkh).unwrap();
        dbg!(&key);
        let derived = key.inner.derive(22).unwrap();
        dbg!(&derived);
    }
}
