// NOTE: This is a work in progress and I bet I'll refactor it a lot;
// it needs to stay opaque!

// TODO: I bet we could turn this into an extension trait.

use crate::{Error, Result};

use rand::distributions::Distribution;
use rand::Rng;
use std::collections::HashMap;
use std::hash::Hash;

/// An IdMap is map from identifiers to keys, along with a distribution
/// for allocating new identifiers.
///
/// We use it to implement maps for circuit IDs and stream IDs.
pub struct IdMap<ID, DST, VAL>
where
    ID: Hash + Eq + Clone,
    DST: Distribution<ID>,
{
    d: DST,
    m: HashMap<ID, VAL>,
}

impl<ID, DST, VAL> IdMap<ID, DST, VAL>
where
    ID: Hash + Eq + Clone,
    DST: Distribution<ID>,
{
    /// Make a new empty map
    pub fn new(dist: DST) -> Self {
        Self {
            d: dist,
            m: HashMap::new(),
        }
    }

    /// Construct a new random identifier for an owned entry in this map.
    /// This can fail if the map is too full.
    fn gen_id<R: Rng>(&self, rng: &mut R) -> Option<ID> {
        // How many times to we try before giving up?
        const MAX_ATTEMPTS: usize = 16;
        for _ in 0..MAX_ATTEMPTS {
            let id = self.d.sample(rng);
            if !self.m.contains_key(&id) {
                return Some(id);
            }
        }
        None
    }

    /// Insert a new entry into this map, allocating an identifier for it.
    pub fn add_ent<R: Rng>(&mut self, rng: &mut R, val: VAL) -> Result<ID> {
        let id = self.gen_id(rng).ok_or(Error::IDRangeFull)?;
        self.m.insert(id.clone(), val);
        Ok(id)
    }

    /// Replace the current entry at 'id' with 'val'.
    pub fn put_ent(&mut self, id: ID, val: VAL) {
        self.m.insert(id, val);
    }

    /// Return a reference to the value at 'id'
    pub fn get(&self, id: &ID) -> Option<&VAL> {
        self.m.get(id)
    }

    /// Remove the entry for `id` on this map, if any.
    pub fn remove(&mut self, id: &ID) -> Option<VAL> {
        self.m.remove(id)
    }

    /// Return the entry for `id` in this map, if any.
    pub fn get_mut(&mut self, id: &ID) -> Option<&mut VAL> {
        self.m.get_mut(&id)
    }

    // TODO: Eventually if we want relay support, we'll need to support
    // IDs chosen by somebody else. But for now, we don't need those.
}
