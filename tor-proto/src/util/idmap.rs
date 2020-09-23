// NOTE: This is a work in progress and I bet I'll refactor it a lot;
// it needs to stay opaque!

use crate::{Error, Result};

use std::collections::HashMap;
use std::hash::{BuildHasher, Hash};

/// Extension trait for hashmap that can add an allocate a new key as
/// needed.
pub trait IdMap<K, V>
where
    K: Hash + Eq + Clone,
{
    /// Insert a new entry into this map, allocating an identifier for it.
    ///
    /// Keep trying until the iterator is done.
    fn add_ent<I: Iterator<Item = K>>(&mut self, iter: &mut I, val: V) -> Result<K>;
}

impl<K, V, S> IdMap<K, V> for HashMap<K, V, S>
where
    K: Hash + Eq + Clone,
    S: BuildHasher,
{
    fn add_ent<I: Iterator<Item = K>>(&mut self, iter: &mut I, val: V) -> Result<K> {
        for i in iter {
            if !self.contains_key(&i) {
                self.insert(i.clone(), val);
                return Ok(i);
            }
        }
        Err(Error::IDRangeFull)
    }
}
