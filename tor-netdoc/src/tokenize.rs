//! Break a string into a set of directory-object Items.

use crate::{Error, Position, Result};
use std::cell::{Ref, RefCell};
use std::str::FromStr;

/// A tagged object that is part of a directory Item.
///
/// This represents a single blob within a pair of "-----BEGIN
/// FOO-----" and "-----END FOO-----".  The data is not guaranteed to
/// be actual base64 when this object is created.
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
pub struct Item<'a> {
    pub off: usize, // don't make this pub.XXXX
    kwd: &'a str,
    args: &'a str,
    /// The arguments, split by whitespace.  This vector is contructed
    /// as needed, using interior mutability.
    split_args: RefCell<Option<Vec<&'a str>>>,
    object: Option<Object<'a>>,
}

/// A cursor into a string that returns Items one by one.
#[derive(Clone, Debug)]
pub struct NetDocReader<'a> {
    /// The string we're parsing.
    s: &'a str,
    /// Our position within the string.
    off: usize,
}

impl<'a> NetDocReader<'a> {
    /// Create a new NetDocReader to split a string into tokens.
    pub fn new(s: &'a str) -> Self {
        NetDocReader { s, off: 0 }
    }
    /// Return the current Position within the string.
    fn get_pos(&self, pos: usize) -> Position {
        Position::from_offset(self.s, pos)
    }
    /// Skip forward by n bytes.
    ///
    /// (Note that standard caveats with byte-oriented processing of
    /// UTF-8 strings apply.)
    fn advance(&mut self, n: usize) -> Result<()> {
        if n > self.remaining() {
            return Err(Error::Internal(Position::from_offset(self.s, self.off)));
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
    /// Try to extract a NL-terminated line from this reader.
    fn get_line(&mut self) -> Result<&'a str> {
        let remainder = &self.s[self.off..];
        let nl_pos = remainder
            .find('\n')
            .ok_or_else(|| Error::TruncatedLine(self.get_pos(self.s.len())))?;
        let mut line = &remainder[..nl_pos];
        self.advance(nl_pos + 1)?;

        // Not in dirspec! XXXX
        if line.ends_with('\r') {
            line = &line[..nl_pos - 1];
        }
        Ok(line)
    }

    /// Try to extract a line that begins with a keyword from this reader.
    ///
    /// Returns a (kwd, args) tuple on success.
    fn get_kwdline(&mut self) -> Result<(&'a str, &'a str)> {
        let pos = self.off;
        let line = self.get_line()?;
        let line = if line.starts_with("opt ") {
            &line[4..]
        } else {
            line
        };
        let mut parts_iter = line.splitn(2, |c| c == ' ' || c == '\t');
        let kwd = match parts_iter.next() {
            Some(k) => k,
            None => return Err(Error::MissingKeyword(self.get_pos(pos))),
        };
        if !keyword_ok(kwd) {
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
    pub fn get_item(&mut self) -> Result<Option<Item<'a>>> {
        if self.remaining() == 0 {
            return Ok(None);
        }
        let off = self.off;
        let (kwd, args) = self.get_kwdline()?;
        let object = self.get_object()?;
        let split_args = RefCell::new(None);
        Ok(Some(Item {
            off,
            kwd,
            args,
            split_args,
            object,
        }))
    }
}

/// Return true iff 's' is a valid keyword.
fn keyword_ok(s: &str) -> bool {
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
impl<'a> Iterator for NetDocReader<'a> {
    type Item = Result<Item<'a>>;
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

impl<'a> Item<'a> {
    /// Return the keyword part of this item.
    pub fn get_kwd(&self) -> &'a str {
        self.kwd
    }
    /// Return the arguments of this item, as a single string.
    pub fn args_as_str(&self) -> &'a str {
        self.args
    }
    /// Return the arguments of this item as a vector.
    pub fn args_as_vec(&self) -> Ref<Vec<&'a str>> {
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
        fn is_sp(c: char) -> bool {
            c == ' ' || c == '\t'
        }
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
        <V as FromStr>::Err: std::error::Error,
    {
        match self.get_arg(idx) {
            None => Ok(None),
            Some(s) => match s.parse() {
                Ok(r) => Ok(Some(r)),
                Err(e) => Err(Error::BadArgument(idx, self.pos(), e.to_string())),
            },
        }
    }
    /// Try to parse the nth argument (if it exists) into some type
    /// that supports FromStr.
    ///
    /// Return an error if the argument doesn't exist.
    pub fn parse_arg<V: FromStr>(&self, idx: usize) -> Result<V>
    where
        <V as FromStr>::Err: std::error::Error,
    {
        match self.parse_optional_arg(idx) {
            Ok(Some(v)) => Ok(v),
            Ok(None) => Err(Error::MissingArgument(self.pos())),
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
            None => Err(Error::MissingObject("entry", self.pos())),
            Some(obj) => {
                if obj.tag != want_tag {
                    Err(Error::WrongObject(self.pos()))
                } else {
                    base64_decode_multiline(obj.data)
                        .map_err(|_| Error::BadObjectBase64(self.pos()))
                }
            }
        }
    }
    /// Return the position of this item without reference to its containing
    /// string.
    pub fn pos(&self) -> Position {
        Position::from_byte(self.off)
    }
    /// Return the Position of this item within s.
    pub fn pos_in(&self, s: &str) -> Position {
        // There are crates that claim they can do this for us and let us
        // throw out 'off' entirely, but I don't trust them.
        Position::from_offset(s, self.off)
    }
}
