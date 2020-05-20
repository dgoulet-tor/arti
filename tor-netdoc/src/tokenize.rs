//! Break a string into a set of directory-object Items.
//!
//! This module defines Item, which represents a basic entry in a
//! directory document, and NetDocReader, which is used to break a
//! string into Items.

use crate::argtype::FromBytes;
use crate::keyword::Keyword;
use crate::{Error, Pos, Result};
use std::cell::{Ref, RefCell};
use std::str::FromStr;

/// Return true iff a given character is "space" according to the rules
/// of dir-spec.txt
pub fn is_sp(c: char) -> bool {
    c == ' ' || c == '\t'
}

/// A tagged object that is part of a directory Item.
///
/// This represents a single blob within a pair of "-----BEGIN
/// FOO-----" and "-----END FOO-----".  The data is not guaranteed to
/// be actual base64 when this object is created: doing so would
/// require either that we parse the base64 twice, or that we allocate
/// a buffer to hold the data before it's needed.
#[derive(Clone, Copy, Debug)]
pub struct Object<'a> {
    tag: &'a str,
    data: &'a str, // not yet guaranteed to be base64.
}

/// A single part of a directory object.
///
/// Each Item -- called an "entry" in dir-spec.txt -- has a keyword, a
/// (possibly empty) set of arguments, and an optional object.
///
/// This is a zero-copy implementation that points to slices within a
/// containing string.
#[derive(Clone, Debug)]
pub struct Item<'a, K: Keyword> {
    kwd: K,
    kwd_str: &'a str,
    args: &'a str,
    /// The arguments, split by whitespace.  This vector is contructed
    /// as needed, using interior mutability.
    split_args: RefCell<Option<Vec<&'a str>>>,
    object: Option<Object<'a>>,
}

/// A cursor into a string that returns Items one by one.
#[derive(Clone, Debug)]
pub struct NetDocReader<'a, K: Keyword> {
    /// The string we're parsing.
    s: &'a str,
    /// Our position within the string.
    off: usize,
    /// Tells Rust it's okay that we are parameterizing on K.
    _k: std::marker::PhantomData<K>,
}

impl<'a, K: Keyword> NetDocReader<'a, K> {
    /// Create a new NetDocReader to split a string into tokens.
    pub fn new(s: &'a str) -> Self {
        NetDocReader {
            s,
            off: 0,
            _k: std::marker::PhantomData,
        }
    }
    /// Return the current Pos within the string.
    fn get_pos(&self, pos: usize) -> Pos {
        Pos::from_offset(self.s, pos)
    }
    /// Skip forward by n bytes.
    ///
    /// (Note that standard caveats with byte-oriented processing of
    /// UTF-8 strings apply.)
    fn advance(&mut self, n: usize) -> Result<()> {
        if n > self.remaining() {
            return Err(Error::Internal(Pos::from_offset(self.s, self.off)));
        }
        self.off += n;
        Ok(())
    }
    /// Return the remaining number of bytes in this reader.
    fn remaining(&self) -> usize {
        self.s.len() - self.off
    }

    /// Return true if the next characters in this reader are `s`
    fn starts_with(&self, s: &str) -> bool {
        self.s[self.off..].starts_with(s)
    }
    /// Try to extract a NL-terminated line from this reader.  Always
    /// remove data if the reader is nonempty.
    fn get_line(&mut self) -> Result<&'a str> {
        let remainder = &self.s[self.off..];
        let mut line;
        if let Some(nl_pos) = remainder.find('\n') {
            self.advance(nl_pos + 1)?;
            line = &remainder[..nl_pos];
        } else {
            self.advance(remainder.len())?; // drain everything.
            return Err(Error::TruncatedLine(self.get_pos(self.s.len())));
        }

        // Not in dirspec! XXXX
        if line.ends_with('\r') {
            line = &line[..line.len() - 1];
        }
        Ok(line)
    }

    /// Try to extract a line that begins with a keyword from this reader.
    ///
    /// Returns a (kwd, args) tuple on success.
    fn get_kwdline(&mut self) -> Result<(&'a str, &'a str)> {
        let pos = self.off;
        let line = self.get_line()?;
        let (line, anno_ok) = if line.starts_with("opt ") {
            (&line[4..], false)
        } else {
            (line, true)
        };
        let mut parts_iter = line.splitn(2, |c| c == ' ' || c == '\t');
        let kwd = match parts_iter.next() {
            Some(k) => k,
            None => return Err(Error::MissingKeyword(self.get_pos(pos))),
        };
        if !keyword_ok(kwd, anno_ok) {
            return Err(Error::BadKeyword(self.get_pos(pos)));
        }
        // XXXX spec should allow unicode in args.
        let args = match parts_iter.next() {
            Some(a) => a,
            None => &"",
        };
        Ok((kwd, args))
    }

    /// Try to extract an Object beginning wrapped within BEGIN/END tags.
    ///
    /// Returns Ok(Some(Object(...))) on success if an object is
    /// found, Ok(None) if no object is found, and Err only if a
    /// corrupt object is found.
    fn get_object(&mut self) -> Result<Option<Object<'a>>> {
        const BEGIN_STR: &str = "-----BEGIN ";
        const END_STR: &str = "-----END ";
        const TAG_END: &str = "-----";
        let pos = self.off;
        if !self.starts_with(BEGIN_STR) {
            return Ok(None);
        }
        let line = self.get_line()?;
        if !line.ends_with(TAG_END) {
            return Err(Error::BadObjectBeginTag(self.get_pos(pos)));
        }
        let tag = &line[BEGIN_STR.len()..(line.len() - TAG_END.len())];
        if !tag_keyword_ok(tag) {
            return Err(Error::BadObjectBeginTag(self.get_pos(pos)));
        }
        let datapos = self.off;
        let (endlinepos, endline) = loop {
            let p = self.off;
            let line = self.get_line()?;
            if line.starts_with(END_STR) {
                break (p, line);
            }
        };
        let data = &self.s[datapos..endlinepos];
        if !endline.ends_with(TAG_END) {
            return Err(Error::BadObjectEndTag(self.get_pos(endlinepos)));
        }
        let endtag = &endline[END_STR.len()..(endline.len() - TAG_END.len())];
        if endtag != tag {
            return Err(Error::BadObjectMismatchedTag(self.get_pos(endlinepos)));
        }
        Ok(Some(Object { tag, data }))
    }

    /// Read the next Item from this NetDocReader.
    ///
    /// If successful, returns Ok(Some(Item)), or Ok(None) if exhausted.
    /// Returns Err on failure.
    ///
    /// Always consumes at least one line if possible; always ends on a
    /// line boundary if one exists.
    pub fn get_item(&mut self) -> Result<Option<Item<'a, K>>> {
        if self.remaining() == 0 {
            return Ok(None);
        }
        let (kwd_str, args) = self.get_kwdline()?;
        let object = self.get_object()?;
        let split_args = RefCell::new(None);
        let kwd = K::from_str(kwd_str);
        Ok(Some(Item {
            kwd,
            kwd_str,
            args,
            split_args,
            object,
        }))
    }
}

/// Return true iff 's' is a valid keyword or annotation.
///
/// (Only allow annotations if `anno_ok` is true.`
fn keyword_ok(mut s: &str, anno_ok: bool) -> bool {
    fn kwd_char_ok(c: char) -> bool {
        match c {
            'A'..='Z' => true,
            'a'..='z' => true,
            '0'..='9' => true,
            '-' => true,
            _ => false,
        }
    }

    if s.is_empty() {
        return false;
    }
    if anno_ok && s.starts_with('@') {
        s = &s[1..];
    }
    // XXXX I think we should disallow initial "-"
    s.chars().all(kwd_char_ok)
}

/// Return true iff 's' is a valid keyword for a BEGIN/END tag.
fn tag_keyword_ok(s: &str) -> bool {
    fn kwd_char_ok(c: char) -> bool {
        match c {
            'A'..='Z' => true,
            'a'..='z' => true,
            '0'..='9' => true,
            '-' => true,
            ' ' => true,
            _ => false,
        }
    }

    if s.is_empty() {
        return false;
    }
    // XXXX I think we should disallow initial "-"
    s.chars().all(kwd_char_ok)
}

/// When used as an Iterator, returns a sequence of Result<Item>.
impl<'a, K: Keyword> Iterator for NetDocReader<'a, K> {
    type Item = Result<Item<'a, K>>;
    fn next(&mut self) -> Option<Self::Item> {
        self.get_item().transpose()
    }
}

/// Helper: as base64::decode(), but allows newlines in the middle of the
/// encoded object.
fn base64_decode_multiline(s: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    // base64 module hates whitespace.
    let mut v = Vec::new();
    for line in s.lines() {
        base64::decode_config_buf(line.trim_end(), base64::STANDARD, &mut v)?;
    }
    Ok(v)
}

impl<'a, K: Keyword> Item<'a, K> {
    /// Return the parsed keyword part of this item.
    pub fn get_kwd(&self) -> K {
        self.kwd
    }
    /// Return the keyword part of this item, as a string.
    pub fn get_kwd_str(&self) -> &'a str {
        self.kwd_str
    }
    /// Return true if the keyword for this item is in 'ks'.
    pub fn has_kwd_in(&self, ks: &[K]) -> bool {
        ks.contains(&self.kwd)
    }
    /// Return the arguments of this item, as a single string.
    pub fn args_as_str(&self) -> &'a str {
        self.args
    }
    /// Return the arguments of this item as a vector.
    fn args_as_vec(&self) -> Ref<Vec<&'a str>> {
        // We're using an interior mutability pattern here to lazily
        // construct the vector.
        if self.split_args.borrow().is_none() {
            self.split_args.replace(Some(self.args().collect()));
        }
        Ref::map(self.split_args.borrow(), |opt| match opt {
            Some(v) => v,
            None => panic!(),
        })
    }
    /// Return an iterator over the arguments of this item.
    pub fn args(&self) -> impl Iterator<Item = &'a str> {
        self.args.split(is_sp).filter(|s| !s.is_empty())
    }
    /// Return the nth argument of this item, if there is one.
    pub fn get_arg(&self, idx: usize) -> Option<&'a str> {
        self.args_as_vec().get(idx).copied()
    }
    /// Try to parse the nth argument (if it exists) into some type
    /// that supports FromStr.
    ///
    /// Returns Ok(None) if the argument doesn't exist.
    pub fn parse_optional_arg<V: FromStr>(&self, idx: usize) -> Result<Option<V>>
    where
        Error: From<V::Err>,
    {
        match self.get_arg(idx) {
            None => Ok(None),
            Some(s) => match s.parse() {
                Ok(r) => Ok(Some(r)),
                Err(e) => {
                    let e: Error = e.into();
                    Err(e.or_at_pos(Pos::at(s)))
                }
            },
        }
    }
    /// Try to parse the nth argument (if it exists) into some type
    /// that supports FromStr.
    ///
    /// Return an error if the argument doesn't exist.
    pub fn parse_arg<V: FromStr>(&self, idx: usize) -> Result<V>
    where
        Error: From<V::Err>,
    {
        match self.parse_optional_arg(idx) {
            Ok(Some(v)) => Ok(v),
            Ok(None) => Err(Error::MissingArgument(self.arg_pos(idx))),
            Err(e) => Err(e),
        }
    }
    /// Return the number of arguments for this Item
    pub fn n_args(&self) -> usize {
        self.args().count()
    }
    /// Return true iff this Item has an associated object.
    pub fn has_obj(&self) -> bool {
        self.object.is_some()
    }
    /// Try to decode the base64 contents of this Item's associated object.
    pub fn get_obj(&self, want_tag: &str) -> Result<Vec<u8>> {
        match self.object {
            None => Err(Error::MissingObject("entry", self.end_pos())),
            Some(obj) => {
                if obj.tag != want_tag {
                    Err(Error::WrongObject(Pos::at(obj.tag)))
                } else {
                    base64_decode_multiline(obj.data)
                        .map_err(|_| Error::BadObjectBase64(Pos::at(obj.data)))
                }
            }
        }
    }
    /// Try to decode the base64 contents of this item's associated object
    /// as a given type that implements FromBytes.
    pub fn parse_obj<V: FromBytes>(&self, want_tag: &str) -> Result<V> {
        let bytes = self.get_obj(want_tag)?;
        let p = Pos::at(self.object.unwrap().data);
        V::from_vec(bytes, p).map_err(|e| e.at_pos(p))
    }
    /// Return the position of this item.
    ///
    /// This position won't be useful unless it is later contextualized
    /// with the containing string.
    pub fn pos(&self) -> Pos {
        Pos::at(self.kwd_str)
    }
    /// Return the position of this Item in a string.
    ///
    /// Returns None if this item doesn't actually belong to the string.
    pub fn offset_in(&self, s: &str) -> Option<usize> {
        crate::util::str_offset(s, self.kwd_str)
    }
    /// Return the position of the n'th argument of this item.
    ///
    /// If this item does not have a n'th argument, return the
    /// position of the end of the final argument.
    pub fn arg_pos(&self, n: usize) -> Pos {
        let args = self.args_as_vec();
        if n < args.len() {
            Pos::at(args[n])
        } else {
            self.last_arg_end_pos()
        }
    }
    /// Return the position at the end of the last argument.
    fn last_arg_end_pos(&self) -> Pos {
        let args = self.args_as_vec();
        if args.len() >= 1 {
            let last_arg = args[args.len() - 1];
            Pos::at_end_of(last_arg)
        } else {
            Pos::at_end_of(self.kwd_str)
        }
    }
    /// Return the position of the end of this object.
    fn end_pos(&self) -> Pos {
        match self.object {
            Some(o) => Pos::at_end_of(o.data),
            None => self.last_arg_end_pos(),
        }
    }
}

/// Represents an Item that might not be present, whose arguments we
/// want to inspect.  If the Item is there, this acts like a proxy to the
/// item; otherwise, it treats the item as having no arguments.

pub struct MaybeItem<'a, 'b, K: Keyword>(Option<&'a Item<'b, K>>);

// All methods here are as for Item.
impl<'a, 'b, K: Keyword> MaybeItem<'a, 'b, K> {
    pub fn from_option(opt: Option<&'a Item<'b, K>>) -> Self {
        MaybeItem(opt)
    }
    pub fn parse_arg<V: FromStr>(&self, idx: usize) -> Result<Option<V>>
    where
        Error: From<V::Err>,
    {
        match self.0 {
            Some(item) => item.parse_arg(idx).map(Some),
            None => Ok(None), // XXXX is this correct?
        }
    }
    #[allow(dead_code)]
    pub fn parse_optional_arg<V: FromStr>(&self, idx: usize) -> Result<Option<V>>
    where
        Error: From<V::Err>,
    {
        match self.0 {
            Some(item) => item.parse_optional_arg(idx),
            None => Ok(None),
        }
    }
    #[allow(dead_code)]
    pub fn args_as_str(&self) -> Option<&str> {
        self.0.map(|item| item.args_as_str())
    }
    #[allow(dead_code)]
    pub fn parse_args_as_str<V: FromStr>(&self) -> Result<Option<V>>
    where
        Error: From<V::Err>,
    {
        match self.0 {
            Some(item) => Ok(Some(item.args_as_str().parse::<V>()?)),
            None => Ok(None),
        }
    }
    #[allow(dead_code)]
    pub fn get_obj(&self, want_tag: &str) -> Result<Option<Vec<u8>>> {
        match self.0 {
            Some(item) => Ok(Some(item.get_obj(want_tag)?)),
            None => Ok(None),
        }
    }
}

pub trait ItemResult<K: Keyword> {
    /// Return true if this is an ok result with the keyword 'k'
    fn is_ok_with_kwd(&self, k: K) -> bool {
        self.is_ok_with_kwd_in(&[k])
    }
    /// Return true if this is an ok result with a keyword in the slice 'ks'
    fn is_ok_with_kwd_in(&self, ks: &[K]) -> bool;
    /// Return true if this is an ok result with a keyword not in the slice 'ks'
    fn is_ok_with_kwd_not_in(&self, ks: &[K]) -> bool;
}

impl<'a, K: Keyword> ItemResult<K> for Result<Item<'a, K>> {
    fn is_ok_with_kwd_in(&self, ks: &[K]) -> bool {
        match self {
            Ok(item) => item.has_kwd_in(ks),
            Err(_) => false,
        }
    }
    fn is_ok_with_kwd_not_in(&self, ks: &[K]) -> bool {
        match self {
            Ok(item) => !item.has_kwd_in(ks),
            Err(_) => false,
        }
    }
}
