use alloc::collections::BTreeMap;
use bitcoin::{PublicKey, script::PushBytesBuf};

#[derive(Debug)]
pub struct KeyRegistry<'a> {
    keys: BTreeMap<&'a str, PublicKey>,
    hashes: BTreeMap<&'a str, PushBytesBuf>,
}

impl<'a> Default for KeyRegistry<'a> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> KeyRegistry<'a> {
    #[inline]
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
            hashes: BTreeMap::new(),
        }
    }

    #[inline]
    pub fn add_key(&mut self, key: &'a str, public_key: PublicKey) {
        self.keys.insert(key, public_key);
    }

    #[inline]
    pub fn add_hash(&mut self, hash: &'a str, data: PushBytesBuf) {
        self.hashes.insert(hash, data);
    }

    #[inline]
    pub fn get_key(&self, key: &'a str) -> Option<&PublicKey> {
        self.keys.get(key)
    }

    #[inline]
    pub fn get_hash(&self, hash: &'a str) -> Option<&PushBytesBuf> {
        self.hashes.get(hash)
    }
}
