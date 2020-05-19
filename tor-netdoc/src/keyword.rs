use crate::rules;
use std::hash::Hash;

/// A Keyword identifies the possible types of a keyword for an Item.
///
/// These do not map one-to-one to Item strings: several Item strings
/// may be placed in a single Keyword -- for example, when their order
/// is signficant with respect to one another, like "accept" and
/// "reject" in rotuer descriptors.
///
/// Every keyword has an "index", which is a small number suitable for
/// indexing an array.  These are used in Section and SectionRules.
///
/// Turning a string into a keyword cannot fail: there is always an
/// "UNRECOGNIZED" keyword.
///
/// See macro::decl_keyword! for help defining a Keyword type for a
/// network document.
pub trait Keyword: Hash + Eq + PartialEq + Copy + Clone {
    /// Find a Keyword corresponding to a string that appears in a
    /// network document.
    fn from_str(s: &str) -> Self;
    /// Try to find the keyword corresponding to a given index value,
    /// as used in Section and SectionRules.
    fn from_idx(i: usize) -> Option<Self>;
    /// Find a string corresponding to this keyword.  This may not be the
    /// actual string from the document; it is indended for reporting errors.
    fn to_str(&self) -> &'static str;
    /// Return the index for this keyword.
    fn idx(self) -> usize;
    /// Return the number of indices for this keyword.
    fn n_vals() -> usize;
    /// Convert from an index to a human-readable string.
    fn idx_to_str(i: usize) -> &'static str {
        Self::from_idx(i)
            .map(|x| x.to_str())
            .unwrap_or("<out of range>")
    }
    /// Return a new TokenFmtBuilder for creating rules about this keyword.
    fn rule(&self) -> rules::TokenFmtBuilder<Self> {
        rules::TokenFmtBuilder::new(*self)
    }
}
