#![allow(missing_docs)] // XXXX doc once api is settled

use futures::channel::oneshot;
use futures::lock::Mutex;

use std::collections::VecDeque;
use std::sync::Arc;

// XXXX Three problems with this tag:
// XXXX - First, we need to support unauthenticated flow control.
// XXXX - Second, this tag type could be different for each layer (and
// XXXX   will be, once we have v3 onion services working).
// XXXX - Third, we want the comparison to happen with a constant-time
// XXXX   operation.

pub type CircTag = [u8; 20];
pub type NoTag = ();

pub type CircSendWindow = SendWindow<CircInc, CircTag>;
pub type StreamSendWindow = SendWindow<StreamInc, NoTag>;

pub type CircRecvWindow = RecvWindow<CircInc>;
pub type StreamRecvWindow = RecvWindow<StreamInc>;

pub struct SendWindow<I, T>
where
    I: WindowInc,
    T: PartialEq + Eq + Clone,
{
    // TODO could use a bilock if that becomes non-experimental.
    // TODO I wish we could do this without locking; we could make a bunch
    // of these functions non-async if that happened.
    w: Arc<Mutex<SendWindowInner<T>>>,
    _dummy: std::marker::PhantomData<I>,
}

struct SendWindowInner<T>
where
    T: PartialEq + Eq + Clone,
{
    capacity: u16,
    window: u16,
    tags: VecDeque<T>,
    unblock: Option<oneshot::Sender<()>>,
}

pub trait WindowInc {
    fn get_val() -> u16;
}
pub struct CircInc;
impl WindowInc for CircInc {
    fn get_val() -> u16 {
        100
    }
}
pub struct StreamInc;
impl WindowInc for StreamInc {
    fn get_val() -> u16 {
        50
    }
}

impl<I, T> SendWindow<I, T>
where
    I: WindowInc,
    T: PartialEq + Eq + Clone,
{
    pub fn new(window: u16) -> SendWindow<I, T> {
        let increment = I::get_val();
        let capacity = (window + increment - 1) / increment;
        let inner = SendWindowInner {
            capacity: window,
            window,
            tags: VecDeque::with_capacity(capacity as usize),
            unblock: None,
        };
        SendWindow {
            w: Arc::new(Mutex::new(inner)),
            _dummy: std::marker::PhantomData,
        }
    }

    pub fn new_ref(&self) -> Self {
        SendWindow {
            w: Arc::clone(&self.w),
            _dummy: std::marker::PhantomData,
        }
    }

    pub async fn take(&mut self, tag: &T) -> u16 {
        loop {
            let wait_on = {
                let mut w = self.w.lock().await;
                let oldval = w.window;
                if oldval % I::get_val() == 0 && oldval != w.capacity {
                    // We record this tag.
                    // TODO: I'm not choosing this cell in particular
                    // matches the spec, but Tor seems to like it.
                    w.tags.push_back(tag.clone());
                }
                if let Some(val) = w.window.checked_sub(1) {
                    w.window = val;
                    return val;
                }

                // Window is zero; can't send yet.
                let (send, recv) = oneshot::channel::<()>();

                let old = w.unblock.replace(send);
                assert!(old.is_none()); // XXXX can this happen?
                recv
            };
            // Wait on this receiver while _not_ holding the lock.

            // XXXX Danger: can this unwrap fail? I think it can't, since
            // the sender can't be cancelled as long as there's a refcount
            // to it.
            wait_on.await.unwrap()
        }
    }

    pub async fn put(&mut self, tag: T) -> Option<u16> {
        let mut w = self.w.lock().await;

        match w.tags.pop_front() {
            Some(t) if t == tag => {} // this is the right tag.
            _ => {
                return None;
            } // Bad tag or unexpected sendme.
        }

        let v = w.window.checked_add(I::get_val())?;
        w.window = v;

        if let Some(send) = w.unblock.take() {
            // if we get a failure, nothing cares about this window any more.
            // XXXX is that true?
            let _ignore = send.send(());
        }

        Some(v)
    }
}

pub struct RecvWindow<I: WindowInc> {
    window: u16,
    _dummy: std::marker::PhantomData<I>,
}

impl<I: WindowInc> RecvWindow<I> {
    pub fn new(window: u16) -> RecvWindow<I> {
        RecvWindow {
            window,
            _dummy: std::marker::PhantomData,
        }
    }

    pub fn take(&mut self) -> Option<bool> {
        let v = self.window.checked_sub(1);
        if let Some(x) = v {
            self.window = x;
            Some(x % I::get_val() == 0)
        } else {
            None
        }
    }

    pub fn put(&mut self) {
        self.window = self.window.checked_add(I::get_val()).unwrap()
    }
}
