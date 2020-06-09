//! Based on a set of rules, validate a token stream and collect the
//! tokens by type.
//!
//! See the "rules" module for definitions of keywords types and
//! per-keyword rules.
//!
//! The key types in this module are SectionRules, which explains how to
//! validate and partition a stream of Item, and Section, which contains
//! a validated set of Item, ready to be interpreted.
//!
//! # Example
//!
//! (This is an internal API, so see the routerdesc.rs source for an
//! example of use.)

use crate::keyword::Keyword;
use crate::rules::*;
use crate::tokenize::*;
use crate::{Error, Result};

/// Describe the rules for one section of a document.
///
/// The rules are represented as a mapping from token index to
/// rules::TokenFmt.
pub struct SectionRules<T: Keyword> {
    rules: Vec<Option<TokenFmt<T>>>,
}

/// The entry or entries for a particular keyword within a document.
#[derive(Clone)]
enum TokVal<'a, K: Keyword> {
    /// No value has been found.
    None,
    /// A single value has been found; we're storing it in place.
    ///
    /// We use a one-element array here so that we can return a slice
    /// of the array.
    Some([Item<'a, K>; 1]),
    /// Multiple vlaues have been found; they go in a vector.
    Multi(Vec<Item<'a, K>>),
}
impl<'a, K: Keyword> TokVal<'a, K> {
    /// Return the number of Items for this value.
    fn count(&self) -> usize {
        match self {
            TokVal::None => 0,
            TokVal::Some(_) => 1,
            TokVal::Multi(v) => v.len(),
        }
    }
    /// Return the first Item for this value, or None if there wasn't one.
    fn first(&self) -> Option<&Item<'a, K>> {
        match self {
            TokVal::None => None,
            TokVal::Some([t]) => Some(t),
            TokVal::Multi(v) => Some(&v[0]),
        }
    }
    /// Return the Item for this value, if there is exactly one.
    fn singleton(&self) -> Option<&Item<'a, K>> {
        match self {
            TokVal::None => None,
            TokVal::Some([t]) => Some(t),
            TokVal::Multi(_) => None,
        }
    }
    /// Return all the Items for this value, as a slice.
    fn as_slice(&self) -> &[Item<'a, K>] {
        match self {
            TokVal::None => &[],
            TokVal::Some(t) => &t[..],
            TokVal::Multi(v) => &v[..],
        }
    }
    /// Return the last Item for this value, if any.
    fn last(&self) -> Option<&Item<'a, K>> {
        match self {
            TokVal::None => None,
            TokVal::Some([t]) => Some(&t),
            TokVal::Multi(v) => Some(&v[v.len() - 1]),
        }
    }
}

/// A Section is the result of sorting a document's entries by keyword.
pub struct Section<'a, T: Keyword> {
    /// Map from Keyword index to TokVal
    v: Vec<TokVal<'a, T>>,
    first: Option<T>,
    last: Option<T>,
}

impl<'a, T: Keyword> Section<'a, T> {
    /// Make a new empty Section.
    fn new() -> Self {
        let n = T::n_vals();
        let mut v = Vec::with_capacity(n);
        v.resize(n, TokVal::None);
        Section {
            v,
            first: None,
            last: None,
        }
    }
    /// Helper: return the tokval for some Keyword.
    fn get_tokval(&self, t: T) -> &TokVal<'a, T> {
        let idx = t.idx();
        &self.v[idx]
    }
    /// Return all the Items for some Keyword, as a slice.
    pub fn get_slice(&self, t: T) -> &[Item<'a, T>] {
        self.get_tokval(t).as_slice()
    }
    /// Return a single Item for some Keyword, if there is exactly one.
    pub fn get(&self, t: T) -> Option<&Item<'a, T>> {
        self.get_tokval(t).singleton()
    }
    /// Return a single Item for some Keyword, giving an error if there
    /// is not exactly one.
    ///
    /// It is usually a mistake to use this function on a Keyword that is
    /// not required.
    pub fn get_required(&self, t: T) -> Result<&Item<'a, T>> {
        self.get(t).ok_or_else(|| Error::MissingToken(t.to_str()))
    }
    /// Return a proxy MaybeItem object for some keyword.
    //
    /// A MaybeItem is used to represent an object that might or might
    /// not be there.
    pub fn maybe<'b>(&'b self, t: T) -> MaybeItem<'b, 'a, T> {
        MaybeItem::from_option(self.get(t))
    }
    /// Return the first item that was accepted for this section, or None
    /// if no items were accepted for this section.
    #[allow(dead_code)]
    pub fn first_item(&self) -> Option<&Item<'a, T>> {
        match self.first {
            None => None,
            Some(t) => self.get_tokval(t).first(),
        }
    }
    /// Return the last item that was accepted for this section, or None
    /// if no items were accepted for this section.
    #[allow(dead_code)]
    pub fn last_item(&self) -> Option<&Item<'a, T>> {
        match self.last {
            None => None,
            Some(t) => self.get_tokval(t).last(),
        }
    }
    /// Insert an `item`.
    ///
    /// The `item` must have parsed Keyword `t`.
    fn add_tok(&mut self, t: T, item: Item<'a, T>) {
        let idx = Keyword::idx(t);
        if idx >= self.v.len() {
            self.v.resize(idx + 1, TokVal::None);
        }
        let m = &mut self.v[idx];

        match m {
            TokVal::None => *m = TokVal::Some([item]),
            TokVal::Some([x]) => {
                *m = TokVal::Multi(vec![x.clone(), item]);
            }
            TokVal::Multi(ref mut v) => {
                v.push(item);
            }
        };
        if self.first.is_none() {
            self.first = Some(t);
        }
        self.last = Some(t);
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
        let rule: TokenFmt<_> = t.into();
        let idx = rule.get_kwd().idx();
        assert!(self.rules[idx].is_none());
        self.rules[idx] = Some(rule);
    }

    /// Parse a stream of tokens into a Section object without (fully)
    /// verifying them.
    ///
    /// Some errors are detected early, but others only show up later
    /// when we validate more carefully.
    fn parse_unverified<'a, I>(&self, tokens: &mut I, section: &mut Section<'a, T>) -> Result<()>
    where
        I: Iterator<Item = Result<Item<'a, T>>>,
    {
        for item in tokens {
            let item = item?;

            let tok = item.get_kwd();
            let tok_idx = tok.idx();
            if let Some(rule) = &self.rules[tok_idx] {
                // we want this token.
                assert!(rule.get_kwd() == tok);
                section.add_tok(tok, item);
                rule.check_multiplicity(section.v[tok_idx].as_slice())?;
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
                    rule.check_multiplicity(t.as_slice())?;
                    // The number is right. Check each individual item.
                    for item in t.as_slice() {
                        rule.check_item(item)?
                    }
                }
            }
        }

        Ok(())
    }

    /// Parse a stream of tokens into a validated section.
    pub fn parse<'a, I>(&self, tokens: &mut I) -> Result<Section<'a, T>>
    where
        I: Iterator<Item = Result<Item<'a, T>>>,
    {
        let mut section = Section::new();
        self.parse_unverified(tokens, &mut section)?;
        self.validate(&section)?;
        // TODO: unrecognized tokens with objects won't actually get their
        // objects checked for valid base64
        Ok(section)
    }
}
