use crate::tokenize::Item;
use crate::{Error, Result};
use std::hash::Hash;

pub trait Keyword: Hash + Eq + PartialEq + Copy + Clone {
    fn from_str(s: &str) -> Self;
    fn from_idx(i: usize) -> Option<Self>;
    fn to_str(&self) -> &'static str;
    fn idx(self) -> usize;
    fn n_vals() -> usize;
    fn idx_to_str(i: usize) -> &'static str {
        Self::from_idx(i)
            .map(|x| x.to_str())
            .unwrap_or("<out of range>")
    }
}

#[derive(Copy, Clone)]
pub enum ObjKind {
    NoObj,
    RequireObj,
    ObjOk,
}

// XXXX too public.
#[derive(Clone)]
pub struct TokenFmt<T: Keyword> {
    pub kwd: T,
    min_args: Option<usize>,
    max_args: Option<usize>,
    pub required: bool,
    pub may_repeat: bool,
    obj: ObjKind,
}

impl<T: Keyword> TokenFmt<T> {
    /// Check whether a single Item matches this TokenFmt rule, with respect
    /// to its number of arguments.
    fn item_matches_args<'a>(&self, t: T, item: &Item<'a>) -> Result<()> {
        let n_args = item.n_args();
        if let Some(max) = self.max_args {
            if n_args > max {
                return Err(Error::TooManyArguments(t.to_str(), item.pos()));
            }
        }
        if let Some(min) = self.min_args {
            if n_args < min {
                return Err(Error::TooFewArguments(t.to_str(), item.pos()));
            }
        }
        Ok(())
    }

    /// Check whether a single Item matches a TokenFmt rule, with respect
    /// to its object's presence and type.
    ///
    /// TODO: Move this to rules?
    fn item_matches_obj<'a>(&self, t: T, item: &Item<'a>) -> Result<()> {
        match (&self.obj, item.has_obj()) {
            (ObjKind::NoObj, true) => Err(Error::UnexpectedObject(t.to_str(), item.pos())),
            (ObjKind::RequireObj, false) => Err(Error::MissingObject(t.to_str(), item.pos())),
            (_, _) => Ok(()),
        }
    }

    /// Check whether a single item has the right number of arguments
    /// and object.
    pub fn check_item<'a>(&self, t: T, item: &Item<'a>) -> Result<()> {
        self.item_matches_args(t, item)?;
        self.item_matches_obj(t, item)
    }
}

pub struct TokenFmtBuilder<T: Keyword>(TokenFmt<T>);

impl<T: Keyword> From<TokenFmtBuilder<T>> for TokenFmt<T> {
    fn from(builder: TokenFmtBuilder<T>) -> Self {
        builder.0
    }
}

impl<T: Keyword> TokenFmtBuilder<T> {
    pub fn new(t: T) -> Self {
        Self(TokenFmt {
            kwd: t,
            min_args: None,
            max_args: None,
            required: false,
            may_repeat: false,
            obj: ObjKind::NoObj,
        })
    }

    pub fn idx(&self) -> usize {
        self.0.kwd.idx()
    }

    pub fn required(self) -> Self {
        Self(TokenFmt {
            required: true,
            ..self.0
        })
    }
    pub fn may_repeat(self) -> Self {
        Self(TokenFmt {
            may_repeat: true,
            ..self.0
        })
    }

    pub fn no_args(self) -> Self {
        Self(TokenFmt {
            max_args: Some(0),
            ..self.0
        })
    }
    pub fn args<R>(self, r: R) -> Self
    where
        R: std::ops::RangeBounds<usize>,
    {
        use std::ops::Bound::*;
        let min_args = match r.start_bound() {
            Included(x) => Some(*x),
            Excluded(x) => Some(*x + 1),
            Unbounded => None,
        };
        let max_args = match r.end_bound() {
            Included(x) => Some(*x),
            Excluded(x) => Some(*x - 1),
            Unbounded => None,
        };
        Self(TokenFmt {
            min_args,
            max_args,
            ..self.0
        })
    }
    pub fn obj_optional(self) -> Self {
        Self(TokenFmt {
            obj: ObjKind::ObjOk,
            ..self.0
        })
    }
    pub fn obj_required(self) -> Self {
        Self(TokenFmt {
            obj: ObjKind::RequireObj,
            ..self.0
        })
    }
}
