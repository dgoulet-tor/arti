//! Based on a set of rules, validate a token stream and collect the
//! tokens by type.
//!
//! See the "rules" module for definitions of rules that are used to
//! govern this process.
//!
//! # Example
//!
//! This is an internal API, so see the routerdesc.rs source for an
//! example of use.

use crate::rules::*;
use crate::tokenize::*;
use crate::{Error, Position, Result};
use std::str::FromStr;

/// Describe the rules for one section of a document.
///
/// The rules are represented as a mapping from token index to
/// rules::TokenFmt.
pub struct SectionRules<T: Keyword> {
    rules: Vec<Option<TokenFmt<T>>>,
}

/// The entry or entries for a particular keyword within a document.
#[derive(Clone)]
enum TokVal<'a> {
    /// No value has been found.
    None,
    /// A single value has been found; we're storing it in place.
    ///
    /// We use a one-element array here so that we can return a slice
    /// of the array.
    Some([Item<'a>; 1]),
    /// Multiple vlaues have been found; they go in a vector.
    Multi(Vec<Item<'a>>),
}
impl<'a> TokVal<'a> {
    /// Return the number of Items for this value.
    fn count(&self) -> usize {
        match self {
            TokVal::None => 0,
            TokVal::Some(_) => 1,
            TokVal::Multi(v) => v.len(),
        }
    }
    /// Return the first Item for this value, or None if there wasn't one.
    fn first(&self) -> Option<&Item<'a>> {
        match self {
            TokVal::None => None,
            TokVal::Some([t]) => Some(t),
            TokVal::Multi(v) => Some(&v[0]),
        }
    }
    /// Return the second Item for this value, or None if there wasn't one.
    ///
    /// Used to make duplicate-token errors.
    fn second(&self) -> Option<&Item<'a>> {
        match self {
            TokVal::Multi(v) if v.len() > 1 => Some(&v[1]),
            _ => None,
        }
    }
    /// Return the Item for this value, if there is exactly one.
    fn singleton(&self) -> Option<&Item<'a>> {
        match self {
            TokVal::None => None,
            TokVal::Some([t]) => Some(t),
            TokVal::Multi(_) => None,
        }
    }
    /// Return all the Items for this value, as a slice.
    fn as_slice(&self) -> &[Item<'a>] {
        match self {
            TokVal::None => &[],
            TokVal::Some(t) => &t[..],
            TokVal::Multi(v) => &v[..],
        }
    }
}

/// A Section is the result of sorting a document's entries by keyword.
pub struct Section<'a, T: Keyword> {
    /// Map from Keyword index to TokVal
    v: Vec<TokVal<'a>>,
    /// Tells Rust it's okay that we are parameterizing on T.
    _t: std::marker::PhantomData<T>,
}

impl<'a, T: Keyword> Section<'a, T> {
    /// Make a new empty Section.
    fn new() -> Self {
        let n = T::n_vals();
        let mut v = Vec::with_capacity(n);
        v.resize(n, TokVal::None);
        Section {
            v,
            _t: std::marker::PhantomData,
        }
    }
    /// Helper: return the tokval for some Keyword.
    fn get_tokval(&self, t: T) -> &TokVal<'a> {
        let idx = t.idx();
        &self.v[idx]
    }
    /// Return all the Items for some Keyword, as a slice.
    pub fn get_slice(&self, t: T) -> &[Item<'a>] {
        self.get_tokval(t).as_slice()
    }
    /// Return a single Item for some Keyword, if there is exactly one.
    pub fn get(&self, t: T) -> Option<&Item<'a>> {
        self.get_tokval(t).singleton()
    }
    /// Return a single Item for some Keyword, giving an error if there
    /// is not exactly one.
    pub fn get_required(&self, t: T) -> Result<&Item<'a>> {
        self.get(t).ok_or(Error::Internal(Position::Unknown)) // XXXX
    }
    /// Return a proxy MaybeItem object for some keyword.
    //
    /// A MaybeItem is used to represent an object that might or might
    /// not be there.
    pub fn maybe<'b>(&'b self, t: T) -> MaybeItem<'b, 'a> {
        MaybeItem(self.get(t))
    }
    /// Parsing implementation: try to insert an `item`.
    ///
    /// The `item` must have parsed Keyword `t`; it is allowed to repeat if
    /// `may_repeat` is true.
    fn add_tok(&mut self, t: T, may_repeat: bool, item: Item<'a>) -> Result<()> {
        let idx = Keyword::idx(t);
        if idx >= self.v.len() {
            self.v.resize(idx + 1, TokVal::None);
        }
        let m = &mut self.v[idx];

        match m {
            TokVal::None => *m = TokVal::Some([item]),
            TokVal::Some([x]) => {
                if !may_repeat {
                    return Err(Error::DuplicateToken(t.to_str(), item.pos()));
                }
                *m = TokVal::Multi(vec![x.clone(), item]);
            }
            TokVal::Multi(ref mut v) => {
                v.push(item);
            }
        };
        Ok(())
    }
}

/// Check whether a single Item matches a TokenFmt rule, with respect
/// to its number of arguments.
///
/// TODO: Move this to rules?
fn item_matches_fmt_args<'a, T: Keyword>(t: T, fmt: &TokenFmt<T>, item: &Item<'a>) -> Result<()> {
    let n_args = item.n_args();
    if let Some(max) = fmt.max_args {
        if n_args > max {
            return Err(Error::TooManyArguments(t.to_str(), item.pos()));
        }
    }
    if let Some(min) = fmt.min_args {
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
fn item_matches_fmt_obj<'a, T: Keyword>(t: T, fmt: &TokenFmt<T>, item: &Item<'a>) -> Result<()> {
    match (&fmt.obj, item.has_obj()) {
        (ObjKind::NoObj, true) => Err(Error::UnexpectedObject(t.to_str(), item.pos())),
        (ObjKind::RequireObj, false) => Err(Error::MissingObject(t.to_str(), item.pos())),
        (_, _) => Ok(()),
    }
}

impl<T: Keyword> SectionRules<T> {
    /// Create a new SectionRules with no rules.
    ///
    /// By default, no Keyword is allowed by this SectionRules.
    pub fn new() -> Self {
        let n = T::n_vals();
        let mut rules = Vec::with_capacity(n);
        rules.resize(n, None);
        SectionRules { rules }
    }

    /// Add a rule to this SectionRules, based on a TokenFmtBuilder.
    ///
    /// Requires that no rule yet exists for the provided keyword.
    pub fn add(&mut self, t: TokenFmtBuilder<T>) {
        let idx = t.idx();
        assert!(self.rules[idx].is_none());
        self.rules[idx] = Some(t.into());
    }

    /// Parse a stream of tokens into a Section object without (fully)
    /// verifying them.
    ///
    /// Some errors are detected early, but others only show up later
    /// when we validate more carefully.
    fn parse_unverified<'a, I>(&self, tokens: &mut I, section: &mut Section<'a, T>) -> Result<()>
    where
        I: Iterator<Item = Result<Item<'a>>>,
    {
        for item in tokens {
            let item = item?;

            let tok = T::from_str(item.get_kwd());
            let tok_idx = tok.idx();
            if let Some(rule) = &self.rules[tok_idx] {
                // we want this token.
                assert!(rule.kwd == tok);
                section.add_tok(tok, rule.may_repeat, item)?;
            } else {
                // We don't have a rule for this token.
                return Err(Error::UnexpectedToken(tok.to_str(), item.pos()));
            }
        }
        Ok(())
    }

    /// Check whether the tokens in a section we've parsed conform to
    /// these rules.
    fn validate<'a>(&self, s: &Section<'a, T>) -> Result<()> {
        // If there are more items in the section than we have rules for,
        // they may be unexpected.
        if s.v.len() > self.rules.len() {
            for (idx, t) in s.v.iter().enumerate().skip(self.rules.len()) {
                if let Some(item) = t.first() {
                    let tokname = T::idx_to_str(idx);
                    return Err(Error::UnexpectedToken(tokname, item.pos()));
                }
            }
        }

        // Iterate over every item, and make sure it matches the
        // corresponding rule.
        for (idx, (rule, t)) in self.rules.iter().zip(s.v.iter()).enumerate() {
            match rule {
                None => {
                    // We aren't supposed to have any of these.
                    if t.count() > 0 {
                        let tokname = T::idx_to_str(idx);
                        return Err(Error::UnexpectedToken(tokname, t.first().unwrap().pos()));
                    }
                }
                Some(rule) => {
                    // We're allowed to have this. Is the number right?
                    if t.count() == 0 && rule.required {
                        return Err(Error::MissingToken(T::idx_to_str(idx)));
                    } else if t.count() > 1 && !rule.may_repeat {
                        return Err(Error::DuplicateToken(
                            T::idx_to_str(idx),
                            t.second().unwrap().pos(),
                        ));
                    }
                    // The number is right. Check each individual item.
                    for item in t.as_slice() {
                        let tok = T::from_idx(idx).unwrap();
                        item_matches_fmt_args(tok, rule, item)?;
                        item_matches_fmt_obj(tok, rule, item)?;
                    }
                }
            }
        }

        Ok(())
    }

    /// Parse a stream of tokens into a validated section.
    pub fn parse<'a, I>(&self, tokens: &mut I) -> Result<Section<'a, T>>
    where
        I: Iterator<Item = Result<Item<'a>>>,
    {
        let mut section = Section::new();
        self.parse_unverified(tokens, &mut section)?;
        self.validate(&section)?;
        Ok(section)
    }
}

/// Represents an Item that might not be present, whose arguments we
/// want to inspect.  If the Item is there, this acts like a proxy to the
/// item; otherwise, it treats the item as having no arguments.

pub struct MaybeItem<'a, 'b>(Option<&'a Item<'b>>);

// All methods here are as for Item.
impl<'a, 'b> MaybeItem<'a, 'b> {
    pub fn parse_arg<V: FromStr>(&self, idx: usize) -> Result<Option<V>>
    where
        <V as FromStr>::Err: std::error::Error,
    {
        match self.0 {
            Some(item) => item.parse_arg(idx).map(Some),
            None => Ok(None), // XXXX is this correct?
        }
    }
    pub fn parse_optional_arg<V: FromStr>(&self, idx: usize) -> Result<Option<V>>
    where
        <V as FromStr>::Err: std::error::Error,
    {
        match self.0 {
            Some(item) => item.parse_optional_arg(idx),
            None => Ok(None),
        }
    }
    pub fn args_as_str(&self) -> Option<&str> {
        self.0.map(|item| item.args_as_str())
    }
    pub fn get_obj(&self, want_tag: &str) -> Result<Option<Vec<u8>>> {
        match self.0 {
            Some(item) => Ok(Some(item.get_obj(want_tag)?)),
            None => Ok(None),
        }
    }
}
