use super::{AbstractChannel, Pending};
use crate::Result;

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
    fn clone_ref(&self) -> Self {
        use ChannelState::*;
        match self {
            Open(chan) => Open(Arc::clone(chan)),
            Building(pending) => Building(pending.clone()),
            Poisoned(_) => panic!(),
        }
    }

    #[cfg(test)]
    fn unwrap_open(&self) -> Arc<C> {
        match self {
            ChannelState::Open(chan) => Arc::clone(chan),
            _ => panic!("Not an oppen channel"),
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
        let entry = map.entry(ident.clone());
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

#[cfg(test)]
mod test {
    use super::*;
    #[derive(Eq, PartialEq, Debug)]
    struct FakeChannel {
        ident: &'static str,
        usable: bool,
    }
    impl AbstractChannel for FakeChannel {
        type Ident = u8;
        fn ident(&self) -> &Self::Ident {
            &self.ident.as_bytes()[0]
        }
        fn is_usable(&self) -> bool {
            self.usable
        }
    }
    fn ch(ident: &'static str) -> ChannelState<FakeChannel> {
        ChannelState::Open(Arc::new(FakeChannel {
            ident,
            usable: true,
        }))
    }
    fn closed(ident: &'static str) -> ChannelState<FakeChannel> {
        ChannelState::Open(Arc::new(FakeChannel {
            ident,
            usable: false,
        }))
    }

    #[test]
    fn simple_ops() {
        let map = ChannelMap::new();
        use ChannelState::Open;

        assert!(map.replace(b'h', ch("hello")).unwrap().is_none());
        assert!(map.replace(b'w', ch("wello")).unwrap().is_none());

        match map.get(&b'h') {
            Ok(Some(Open(chan))) if chan.ident == "hello" => {}
            _ => panic!(),
        }

        assert!(map.get(&b'W').unwrap().is_none());

        match map.replace(b'h', ch("hebbo")) {
            Ok(Some(Open(chan))) if chan.ident == "hello" => {}
            _ => panic!(),
        }

        assert!(map.remove(&b'Z').unwrap().is_none());
        match map.remove(&b'h') {
            Ok(Some(Open(chan))) if chan.ident == "hebbo" => {}
            _ => panic!(),
        }
    }

    #[test]
    fn rmv_unusable() {
        let map = ChannelMap::new();

        map.replace(b'm', closed("machen")).unwrap();
        map.replace(b'f', ch("feinen")).unwrap();
        map.replace(b'w', closed("wir")).unwrap();
        map.replace(b'F', ch("Fug")).unwrap();

        map.remove_unusable().unwrap();

        assert!(map.get(&b'm').unwrap().is_none());
        assert!(map.get(&b'w').unwrap().is_none());
        assert!(map.get(&b'f').unwrap().is_some());
        assert!(map.get(&b'F').unwrap().is_some());
    }

    #[test]
    fn change() {
        let map = ChannelMap::new();

        map.replace(b'w', ch("wir")).unwrap();
        map.replace(b'm', ch("machen")).unwrap();
        map.replace(b'f', ch("feinen")).unwrap();
        map.replace(b'F', ch("Fug")).unwrap();

        //  Replace Some with Some.
        let (old, v) = map
            .change_state(&b'F', |state| (Some(ch("FUG")), (state, 99_u8)))
            .unwrap();
        assert_eq!(old.unwrap().unwrap_open().ident, "Fug");
        assert_eq!(v, 99);
        assert_eq!(map.get(&b'F').unwrap().unwrap().unwrap_open().ident, "FUG");

        // Replace Some with None.
        let (old, v) = map
            .change_state(&b'f', |state| (None, (state, 123_u8)))
            .unwrap();
        assert_eq!(old.unwrap().unwrap_open().ident, "feinen");
        assert_eq!(v, 123);
        assert!(map.get(&b'f').unwrap().is_none());

        // Replace None with Some.
        let (old, v) = map
            .change_state(&b'G', |state| (Some(ch("Geheimnisse")), (state, "Hi")))
            .unwrap();
        assert!(old.is_none());
        assert_eq!(v, "Hi");
        assert_eq!(
            map.get(&b'G').unwrap().unwrap().unwrap_open().ident,
            "Geheimnisse"
        );

        // Replace None with None
        let (old, v) = map
            .change_state(&b'Q', |state| (None, (state, "---")))
            .unwrap();
        assert!(old.is_none());
        assert_eq!(v, "---");
        assert!(map.get(&b'Q').unwrap().is_none());
    }
}
