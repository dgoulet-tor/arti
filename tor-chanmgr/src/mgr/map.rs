use super::{AbstractChannel, Pending};
use crate::Result;

use tor_llcrypto::pk::ed25519::Ed25519Identity;

use std::collections::{hash_map, HashMap};
use std::sync::Arc;

pub(crate) struct ChannelMap<C: AbstractChannel> {
    /// A map from identity to channel, or to pending channel status.
    ///
    /// (Danger: this uses a blocking mutex close to async code.  This mutex
    /// must never be held while an await is happening.)
    channels: std::sync::Mutex<HashMap<C::Ident, ChannelState<C>>>,
}

// used to ensure that only this module can construct a ChannelState::Poisoned.
pub struct Priv {
    _unused: (),
}

pub(crate) enum ChannelState<C> {
    Open(Arc<C>),
    Building(Pending<C>),
    // XXXX explain what this is for.
    Poisoned(Priv),
}

impl<C> ChannelState<C> {
    pub(super) fn clone_ref(&self) -> Self {
        use ChannelState::*;
        match self {
            Open(chan) => Open(Arc::clone(chan)),
            Building(pending) => Building(pending.clone()),
            Poisoned(_) => panic!(),
        }
    }
}

impl<C: AbstractChannel> ChannelState<C> {
    /// DOCDOC returns true if identity COULD BE `ident`
    fn check_ident(&self, ident: &C::Ident) -> bool {
        match self {
            ChannelState::Open(chan) => chan.ident() == ident,
            ChannelState::Poisoned(_) => false,
            ChannelState::Building(_) => true,
        }
    }
}

impl<C: AbstractChannel> ChannelMap<C> {
    pub(crate) fn new() -> Self {
        ChannelMap {
            channels: std::sync::Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn get(&self, ident: &C::Ident) -> Result<Option<ChannelState<C>>> {
        let map = self.channels.lock()?;
        Ok(map.get(ident).map(ChannelState::clone_ref))
    }

    pub(crate) fn replace(
        &self,
        ident: C::Ident,
        newval: ChannelState<C>,
    ) -> Result<Option<ChannelState<C>>> {
        assert!(newval.check_ident(&ident));
        let mut map = self.channels.lock()?;
        Ok(map.insert(ident, newval))
    }

    pub(crate) fn remove(&self, ident: &C::Ident) -> Result<Option<ChannelState<C>>> {
        let mut map = self.channels.lock()?;
        Ok(map.remove(ident))
    }

    pub(crate) fn remove_unusable(&self) -> Result<()> {
        let mut map = self.channels.lock()?;
        map.retain(|_, state| match state {
            ChannelState::Poisoned(_) => panic!(),
            ChannelState::Open(ch) => ch.is_usable(),
            ChannelState::Building(_) => true,
        });
        Ok(())
    }

    pub(crate) fn change_state<F, V>(&self, ident: &C::Ident, func: F) -> Result<V>
    where
        F: FnOnce(Option<ChannelState<C>>) -> (Option<ChannelState<C>>, V),
    {
        use hash_map::Entry::*;
        let mut map = self.channels.lock()?;
        let mut entry = map.entry(ident.clone());
        match entry {
            Occupied(mut occupied) => {
                // DOCDOC explain what's up here.
                let mut oldent = ChannelState::Poisoned(Priv { _unused: () });
                std::mem::swap(occupied.get_mut(), &mut oldent);
                let (newval, output) = func(Some(oldent));
                match newval {
                    Some(mut newent) => {
                        assert!(newent.check_ident(ident));
                        std::mem::swap(occupied.get_mut(), &mut newent);
                    }
                    None => {
                        occupied.remove();
                    }
                };
                Ok(output)
            }
            Vacant(vacant) => {
                let (newval, output) = func(None);
                if let Some(newent) = newval {
                    assert!(newent.check_ident(ident));
                    vacant.insert(newent);
                }
                Ok(output)
            }
        }
    }
}
