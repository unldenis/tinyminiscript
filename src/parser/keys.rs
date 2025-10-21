use core::str::FromStr;

use alloc::{string::String, vec::Vec};
use bitcoin::bip32;
use bitcoin::hashes::Hash;
use bitcoin::{PubkeyHash, script::Builder, secp256k1};

use crate::descriptor::Descriptor;
use crate::parser::{ParseError, Position};

use alloc::string::ToString;

#[derive(Clone)]
/// A token for a public key - enum-based approach eliminating trait objects
pub struct KeyToken {
    inner: KeyTokenInner,
}

#[derive(Clone)]
pub(crate) enum KeyTokenInner {
    PublicKey(bitcoin::PublicKey),
    XOnlyPublicKey(bitcoin::XOnlyPublicKey),
    ExtendedKey(ExtendedKey),
}

impl KeyToken {
    #[inline]
    pub(crate) fn new(inner: KeyTokenInner) -> Self {
        Self { inner }
    }

    pub fn is_compressed(&self) -> bool {
        match &self.inner {
            KeyTokenInner::PublicKey(pk) => pk.compressed,
            KeyTokenInner::XOnlyPublicKey(_) => true,
            KeyTokenInner::ExtendedKey(_) => true,
        }
    }

    pub fn identifier(&self) -> String {
        match &self.inner {
            KeyTokenInner::PublicKey(pk) => pk.to_string(),
            KeyTokenInner::XOnlyPublicKey(pk) => pk.to_string(),
            KeyTokenInner::ExtendedKey(ext) => ext.identifier(),
        }
    }

    pub fn as_definite_key(&self) -> Option<DefiniteKeyToken> {
        match &self.inner {
            KeyTokenInner::PublicKey(pk) => Some(DefiniteKeyToken::PublicKey(*pk)),
            KeyTokenInner::XOnlyPublicKey(pk) => Some(DefiniteKeyToken::XOnlyPublicKey(*pk)),
            KeyTokenInner::ExtendedKey(_) => None,
        }
    }

    pub fn derive(&self, index: u32) -> Result<Self, String> {
        match &self.inner {
            KeyTokenInner::ExtendedKey(ext) => {
                let derived = ext.derive(index)?;
                Ok(KeyToken {
                    inner: KeyTokenInner::from_definite_key(derived),
                })
            }
            _ => Ok(self.clone()), // Non-extended keys don't need derivation
        }
    }

    // Helper method to create from definite key
    pub fn from_definite_key(key: DefiniteKeyToken) -> Self {
        Self {
            inner: match key {
                DefiniteKeyToken::PublicKey(pk) => KeyTokenInner::PublicKey(pk),
                DefiniteKeyToken::XOnlyPublicKey(pk) => KeyTokenInner::XOnlyPublicKey(pk),
            },
        }
    }
}

impl KeyTokenInner {
    fn from_definite_key(key: DefiniteKeyToken) -> Self {
        match key {
            DefiniteKeyToken::PublicKey(pk) => Self::PublicKey(pk),
            DefiniteKeyToken::XOnlyPublicKey(pk) => Self::XOnlyPublicKey(pk),
        }
    }
}

#[derive(Clone, Copy)]
pub enum DefiniteKeyToken {
    PublicKey(bitcoin::PublicKey),
    XOnlyPublicKey(bitcoin::XOnlyPublicKey),
}

impl DefiniteKeyToken {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            DefiniteKeyToken::PublicKey(pk) => pk.to_bytes().to_vec(),
            DefiniteKeyToken::XOnlyPublicKey(pk) => pk.serialize().to_vec(),
        }
    }

    pub fn push_to_script(&self, builder: Builder) -> Builder {
        match self {
            DefiniteKeyToken::PublicKey(pk) => builder.push_key(pk),
            DefiniteKeyToken::XOnlyPublicKey(pk) => builder.push_x_only_key(pk),
        }
    }

    pub fn pubkey_hash(&self) -> PubkeyHash {
        match self {
            DefiniteKeyToken::PublicKey(pk) => pk.pubkey_hash(),
            DefiniteKeyToken::XOnlyPublicKey(pk) => PubkeyHash::hash(&pk.serialize()),
        }
    }
}

#[cfg(feature = "debug")]
impl core::fmt::Debug for KeyToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.identifier())
    }
}

#[cfg(feature = "debug")]
impl core::fmt::Debug for DefiniteKeyToken {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DefiniteKeyToken::PublicKey(pk) => write!(f, "PublicKey({})", pk),
            DefiniteKeyToken::XOnlyPublicKey(pk) => write!(f, "XOnlyPublicKey({})", pk),
        }
    }
}

#[cfg_attr(feature = "debug", derive(Debug))]
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
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
struct ExtendedKey {
    pub raw: String,
    pub origin: Option<(bip32::Fingerprint, bip32::DerivationPath)>,
    pub key: bip32::Xpub,
    pub path: bip32::DerivationPath,
    pub wildcard: Wildcard,
    pub x_only: bool,
}

impl ExtendedKey {
    #[inline]
    pub fn identifier(&self) -> String {
        self.raw.clone()
    }

    pub fn derive(&self, index: u32) -> Result<DefiniteKeyToken, String> {
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
            Ok(DefiniteKeyToken::XOnlyPublicKey(
                bitcoin::XOnlyPublicKey::from(pubkey.public_key),
            ))
        } else {
            Ok(DefiniteKeyToken::PublicKey(bitcoin::PublicKey::from(
                pubkey.public_key,
            )))
        }
    }
}

impl core::fmt::Display for ExtendedKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        use alloc::string::ToString;

        if let Some((fingerprint, path)) = &self.origin {
            write!(
                f,
                "[{fingerprint}{}{}]",
                if path.is_empty() { "" } else { "/" },
                &path.to_string()
            )?;
        }

        write!(f, "{}", self.key)?;
        write!(
            f,
            "{}{}",
            if self.path.is_empty() { "" } else { "/" },
            &self.path.to_string()
        )?;
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
                let origin_path_str = alloc::format!("m{}", &remaining);
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

        let key = ExtendedKey {
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
        };
        return Ok(KeyToken {
            inner: KeyTokenInner::ExtendedKey(key),
        });
    }

    // Get the key type based on the inner descriptor
    let key = match descriptor {
        Descriptor::Tr => {
            // rust miniscript does not parse directly to xonly key
            // so we need to parse to pubkey and then convert to xonly key

            // Fix: https://github.com/unldenis/tinyminiscript/issues/40
            // pubkey string should be 66 or 130 digits long, got: 64
            if token.0.len() != 66 && token.0.len() != 130 {
                return Err(ParseError::InvalidXOnlyKeyLength {
                    key: token.0,
                    position: token.1,
                    found: token.0.len(),
                });
            }

            let pub_key =
                bitcoin::PublicKey::from_str(token.0).map_err(|_| ParseError::InvalidKey {
                    key: token.0,
                    position: token.1,
                    inner: "Invalid bitcoin::PublicKey key",
                })?;
            KeyTokenInner::XOnlyPublicKey(pub_key.into())
        }
        _ => {
            let pub_key =
                bitcoin::PublicKey::from_str(token.0).map_err(|_| ParseError::InvalidKey {
                    key: token.0,
                    position: token.1,
                    inner: "Invalid bitcoin::PublicKey key",
                })?;
            KeyTokenInner::PublicKey(pub_key)
        }
    };

    Ok(KeyToken { inner: key })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_key() {
        let key = "[aabbccdd/10'/123]tpubDAenfwNu5GyCJWv8oqRAckdKMSUoZjgVF5p8WvQwHQeXjDhAHmGrPa4a4y2Fn7HF2nfCLefJanHV3ny1UY25MRVogizB2zRUdAo7Tr9XAjm/10/*";
        let key = parse_key((key, 0), &Descriptor::Wpkh).unwrap();
        dbg!(&key);
        let derived = key.derive(22).unwrap();
        dbg!(&derived);
    }

    #[test]
    fn test_parse_xonly_key() {
        let key = "020202020202020212131610202020202121316121618171818121715181919190";
        let key = parse_key((key, 0), &Descriptor::Tr).unwrap();
        dbg!(&key);
    }
}
