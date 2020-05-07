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
    pub min_args: Option<usize>,
    pub max_args: Option<usize>,
    pub required: bool,
    pub may_repeat: bool,
    pub obj: ObjKind,
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
