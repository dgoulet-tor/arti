//! Break a string into a set of directory-object Items.
//!
//! This module defines Item, which represents a basic entry in a
//! directory document, and NetDocReader, which is used to break a
//! string into Items.

use crate::parse::keyword::Keyword;
use crate::types::misc::FromBytes;
use crate::util::PauseAt;
use crate::{Error, Pos, Result};
use std::cell::{Ref, RefCell};
use std::str::FromStr;

/// Return true iff a given character is "space" according to the rules
/// of dir-spec.txt
pub fn is_sp(c: char) -> bool {
    c == ' ' || c == '\t'
}
/// Check that all the characters in `s` are valid base64.
///
/// This is not a perfect check for base64ness -- it is mainly meant
/// to help us recover after unterminated base64.
fn b64check(s: &str) -> Result<()> {
    for b in s.bytes() {
        match b {
            b'=' => (),
            b'a'..=b'z' => (),
            b'A'..=b'Z' => (),
            b'0'..=b'9' => (),
            b'/' | b'+' => (),
            _ => {
                return Err(Error::BadObjectBase64(Pos::at(s)));
            }
        };
    }
    Ok(())
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
    data: &'a str,    // not yet guaranteed to be base64.
    endline: &'a str, // used to get position.
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
///
/// (This type isn't used directly, but is returned wrapped in a Peekable.)
#[derive(Debug)]
struct NetDocReaderBase<'a, K: Keyword> {
    /// The string we're parsing.
    s: &'a str,
    /// Our position within the string.
    off: usize,
    /// Tells Rust it's okay that we are parameterizing on K.
    _k: std::marker::PhantomData<K>,
}

impl<'a, K: Keyword> NetDocReaderBase<'a, K> {
    /// Create a new NetDocReader to split a string into tokens.
    fn new(s: &'a str) -> Self {
        NetDocReaderBase {
            s,
            off: 0,
            _k: std::marker::PhantomData,
        }
    }
    /// Return the current Pos within the string.
    fn pos(&self, pos: usize) -> Pos {
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
    fn line(&mut self) -> Result<&'a str> {
        let remainder = &self.s[self.off..];
        let line;
        if let Some(nl_pos) = remainder.find('\n') {
            self.advance(nl_pos + 1)?;
            line = &remainder[..nl_pos];
        } else {
            self.advance(remainder.len())?; // drain everything.
            return Err(Error::TruncatedLine(self.pos(self.s.len())));
        }

        // TODO: we should probably detect \r and do something about it.
        // Just ignoring it isn't the right answer, though.
        Ok(line)
    }

    /// Try to extract a line that begins with a keyword from this reader.
    ///
    /// Returns a (kwd, args) tuple on success.
    fn kwdline(&mut self) -> Result<(&'a str, &'a str)> {
        let pos = self.off;
        let line = self.line()?;
        let (line, anno_ok) = if let Some(rem) = line.strip_prefix("opt ") {
            (rem, false)
        } else {
            (line, true)
        };
        let mut parts_iter = line.splitn(2, |c| c == ' ' || c == '\t');
        let kwd = match parts_iter.next() {
            Some(k) => k,
            // This case seems like it can't happen: split always returns
            // something, apparently.
            None => return Err(Error::MissingKeyword(self.pos(pos))),
        };
        if !keyword_ok(kwd, anno_ok) {
            return Err(Error::BadKeyword(self.pos(pos)));
        }
        // XXXX spec should allow unicode in args.
        let args = match parts_iter.next() {
            Some(a) => a,
            // take a zero-length slice, so it will be within the string.
            None => &kwd[kwd.len()..],
        };
        Ok((kwd, args))
    }

    /// Try to extract an Object beginning wrapped within BEGIN/END tags.
    ///
    /// Returns Ok(Some(Object(...))) on success if an object is
    /// found, Ok(None) if no object is found, and Err only if a
    /// corrupt object is found.
    fn object(&mut self) -> Result<Option<Object<'a>>> {
        const BEGIN_STR: &str = "-----BEGIN ";
        const END_STR: &str = "-----END ";
        const TAG_END: &str = "-----";
        let pos = self.off;
        if !self.starts_with(BEGIN_STR) {
            return Ok(None);
        }
        let line = self.line()?;
        if !line.ends_with(TAG_END) {
            return Err(Error::BadObjectBeginTag(self.pos(pos)));
        }
        let tag = &line[BEGIN_STR.len()..(line.len() - TAG_END.len())];
        if !tag_keyword_ok(tag) {
            return Err(Error::BadObjectBeginTag(self.pos(pos)));
        }
        let datapos = self.off;
        let (endlinepos, endline) = loop {
            let p = self.off;
            let line = self.line()?;
            if line.starts_with(END_STR) {
                break (p, line);
            }
            // Exit if this line isn't plausible base64.  Otherwise,
            // an unterminated base64 block could potentially
            // "consume" all the rest of the string, which would stop
            // us from recovering.
            b64check(line).map_err(|e| e.within(self.s))?;
        };
        let data = &self.s[datapos..endlinepos];
        if !endline.ends_with(TAG_END) {
            return Err(Error::BadObjectEndTag(self.pos(endlinepos)));
        }
        let endtag = &endline[END_STR.len()..(endline.len() - TAG_END.len())];
        if endtag != tag {
            return Err(Error::BadObjectMismatchedTag(self.pos(endlinepos)));
        }
        Ok(Some(Object { tag, data, endline }))
    }

    /// Read the next Item from this NetDocReaderBase.
    ///
    /// If successful, returns Ok(Some(Item)), or Ok(None) if exhausted.
    /// Returns Err on failure.
    ///
    /// Always consumes at least one line if possible; always ends on a
    /// line boundary if one exists.
    fn item(&mut self) -> Result<Option<Item<'a, K>>> {
        if self.remaining() == 0 {
            return Ok(None);
        }
        let (kwd_str, args) = self.kwdline()?;
        let object = self.object()?;
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
    if s.starts_with('-') {
        return false;
    }
    s.chars().all(kwd_char_ok)
}

/// Return true iff 's' is a valid keyword for a BEGIN/END tag.
fn tag_keyword_ok(s: &str) -> bool {
    s.split(' ').all(|w| keyword_ok(w, false))
}

/// When used as an Iterator, returns a sequence of Result<Item>.
impl<'a, K: Keyword> Iterator for NetDocReaderBase<'a, K> {
    type Item = Result<Item<'a, K>>;
    fn next(&mut self) -> Option<Self::Item> {
        self.item().transpose()
    }
}

/// Helper: as base64::decode(), but allows newlines in the middle of the
/// encoded object.
fn base64_decode_multiline(s: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    // base64 module hates whitespace.
    let mut v = Vec::new();
    let mut s = s.to_string();
    s.retain(|ch| ch != '\n');
    base64::decode_config_buf(s, base64::STANDARD, &mut v)?;
    Ok(v)
}

impl<'a, K: Keyword> Item<'a, K> {
    /// Return the parsed keyword part of this item.
    pub fn kwd(&self) -> K {
        self.kwd
    }
    /// Return the keyword part of this item, as a string.
    pub fn kwd_str(&self) -> &'a str {
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
    fn args_as_vec(&self) -> Ref<'_, Vec<&'a str>> {
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
    pub fn arg(&self, idx: usize) -> Option<&'a str> {
        self.args_as_vec().get(idx).copied()
    }
    /// Return the nth argument of this item, or an error if it isn't there.
    pub fn required_arg(&self, idx: usize) -> Result<&'a str> {
        self.arg(idx)
            .ok_or_else(|| Error::MissingArgument(Pos::at(self.args)))
    }
    /// Try to parse the nth argument (if it exists) into some type
    /// that supports FromStr.
    ///
    /// Returns Ok(None) if the argument doesn't exist.
    pub fn parse_optional_arg<V: FromStr>(&self, idx: usize) -> Result<Option<V>>
    where
        Error: From<V::Err>,
    {
        match self.arg(idx) {
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
    /// Return the tag of this item's associated object, if it has one.
    pub fn obj_tag(&self) -> Option<&'a str> {
        self.object.map(|o| o.tag)
    }
    /// Try to decode the base64 contents of this Item's associated object.
    pub fn obj(&self, want_tag: &str) -> Result<Vec<u8>> {
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
        let bytes = self.obj(want_tag)?;
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
            Some(o) => Pos::at_end_of(o.endline),
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
    pub fn args_as_str(&self) -> Option<&str> {
        self.0.map(|item| item.args_as_str())
    }
    pub fn parse_args_as_str<V: FromStr>(&self) -> Result<Option<V>>
    where
        Error: From<V::Err>,
    {
        match self.0 {
            Some(item) => Ok(Some(item.args_as_str().parse::<V>()?)),
            None => Ok(None),
        }
    }
}

pub trait ItemResult<K: Keyword> {
    /// Return true if this is an ok result with an annotation.
    fn is_ok_with_annotation(&self) -> bool;
    /// Return true if this is an ok result with a non-annotation.
    fn is_ok_with_non_annotation(&self) -> bool;
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
    fn is_ok_with_annotation(&self) -> bool {
        match self {
            Ok(item) => item.kwd().is_annotation(),
            Err(_) => false,
        }
    }
    fn is_ok_with_non_annotation(&self) -> bool {
        match self {
            Ok(item) => !item.kwd().is_annotation(),
            Err(_) => false,
        }
    }
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

/// A peekable cursor into a string that returns Items one by one.
#[derive(Debug)]
pub struct NetDocReader<'a, K: Keyword> {
    // TODO: I wish there were some way around having this string
    // reference, since we already need one inside NetDocReaderBase.
    s: &'a str,
    tokens: std::iter::Peekable<NetDocReaderBase<'a, K>>,
}

impl<'a, K: Keyword> NetDocReader<'a, K> {
    /// Construct a new NetDocReader to read tokens from `s`.
    pub fn new(s: &'a str) -> Self {
        NetDocReader {
            s,
            tokens: NetDocReaderBase::new(s).peekable(),
        }
    }
    /// Return a reference to the string used for this NetDocReader.
    pub fn str(&self) -> &'a str {
        self.s
    }
    /// Return the peekable iterator over the string's tokens.
    pub fn iter(&mut self) -> &mut std::iter::Peekable<impl Iterator<Item = Result<Item<'a, K>>>> {
        &mut self.tokens
    }
    /// Return a PauseAt wrapper around the peekable iterator in this
    /// NetDocReader that reads tokens until it reaches an element where
    /// 'f' is true.
    pub fn pause_at<F>(&mut self, f: F) -> PauseAt<'_, impl Iterator<Item = Result<Item<'a, K>>>, F>
    where
        F: FnMut(&Result<Item<'a, K>>) -> bool,
    {
        PauseAt::from_peekable(&mut self.tokens, f)
    }
    /// Return a PauseAt wrapper around the peekable iterator in this
    /// NetDocReader that returns all items.
    #[allow(unused)]
    pub fn pauseable(
        &mut self,
    ) -> PauseAt<
        '_,
        impl Iterator<Item = Result<Item<'a, K>>>,
        impl FnMut(&Result<Item<'a, K>>) -> bool,
    > {
        self.pause_at(|_| false)
    }

    /// Return true if there are no more items in this NetDocReader.
    pub fn is_exhausted(&mut self) -> bool {
        self.iter().peek().is_none()
    }

    /// Give an error if there are remaining tokens in this NetDocReader.
    pub fn should_be_exhausted(&mut self) -> Result<()> {
        match self.iter().peek() {
            None => Ok(()),
            Some(Ok(t)) => Err(Error::UnexpectedToken(t.kwd().to_str(), t.pos())),
            Some(Err(e)) => Err(e.clone()),
        }
    }

    /// Return the position from which the underlying reader is about to take
    /// the next token.  Use to make sure that the reader is progressing.
    pub(crate) fn pos(&mut self) -> Pos {
        match self.tokens.peek() {
            Some(Ok(tok)) => tok.pos(),
            Some(Err(e)) => e.pos(),
            None => Pos::at_end_of(self.s),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::parse::macros::test::Fruit;
    use crate::{Error, Pos, Result};

    #[test]
    fn read_simple() {
        use Fruit::*;

        let s = "\
@tasty very much so
opt apple 77
banana 60
cherry 6
-----BEGIN CHERRY SYNOPSIS-----
8J+NkvCfjZLwn42S8J+NkvCfjZLwn42S
-----END CHERRY SYNOPSIS-----
plum hello there
";
        let mut r: NetDocReader<Fruit> = NetDocReader::new(s);

        assert_eq!(r.str(), s);
        assert!(r.should_be_exhausted().is_err()); // it's not exhausted.

        let toks: Result<Vec<_>> = r.iter().collect();
        assert!(r.should_be_exhausted().is_ok());

        let toks = toks.unwrap();
        assert_eq!(toks.len(), 5);
        assert_eq!(toks[0].kwd(), ANN_TASTY);
        assert_eq!(toks[0].n_args(), 3);
        assert_eq!(toks[0].args_as_str(), "very much so");
        assert_eq!(toks[0].arg(1), Some("much"));
        {
            let a: Vec<_> = toks[0].args().collect();
            assert_eq!(a, vec!["very", "much", "so"]);
        }
        assert!(toks[0].parse_arg::<usize>(0).is_err());
        assert!(toks[0].parse_arg::<usize>(10).is_err());
        assert!(!toks[0].has_obj());
        assert_eq!(toks[0].obj_tag(), None);

        assert_eq!(toks[2].pos().within(s), Pos::from_line(3, 1));
        assert_eq!(toks[2].arg_pos(0).within(s), Pos::from_line(3, 8));
        assert_eq!(toks[2].last_arg_end_pos().within(s), Pos::from_line(3, 10));
        assert_eq!(toks[2].end_pos().within(s), Pos::from_line(3, 10));

        assert_eq!(toks[3].kwd(), STONEFRUIT);
        assert_eq!(toks[3].kwd_str(), "cherry"); // not cherry/plum!
        assert_eq!(toks[3].n_args(), 1);
        assert_eq!(toks[3].required_arg(0), Ok("6"));
        assert_eq!(toks[3].parse_arg::<usize>(0), Ok(6));
        assert_eq!(toks[3].parse_optional_arg::<usize>(0), Ok(Some(6)));
        assert_eq!(toks[3].parse_optional_arg::<usize>(3), Ok(None));
        assert!(toks[3].has_obj());
        assert_eq!(toks[3].obj_tag(), Some("CHERRY SYNOPSIS"));
        assert_eq!(
            &toks[3].obj("CHERRY SYNOPSIS").unwrap()[..],
            "🍒🍒🍒🍒🍒🍒".as_bytes()
        );
        assert!(toks[3].obj("PLUOT SYNOPSIS").is_err());
        // this "end-pos" value is questionable!
        assert_eq!(toks[3].end_pos().within(s), Pos::from_line(7, 30));
    }

    #[test]
    fn test_badtoks() {
        use Fruit::*;

        let s = "\
-foobar 9090
apple 3.14159
$hello
unrecognized 127.0.0.1 foo
plum
-----BEGIN WHATEVER-----
8J+NkvCfjZLwn42S8J+NkvCfjZLwn42S
-----END SOMETHING ELSE-----
orange
orange
-----BEGIN WHATEVER-----
not! base64!
-----END WHATEVER-----
guava paste
opt @annotation
orange
-----BEGIN LOBSTER
8J+NkvCfjZLwn42S8J+NkvCfjZLwn42S
-----END SOMETHING ELSE-----
orange
-----BEGIN !!!!!!-----
8J+NkvCfjZLwn42S8J+NkvCfjZLwn42S
-----END !!!!!!-----
cherry
-----BEGIN CHERRY SYNOPSIS-----
8J+NkvCfjZLwn42S8J+NkvCfjZLwn42S
-----END CHERRY SYNOPSIS

truncated line";

        let mut r: NetDocReader<Fruit> = NetDocReader::new(s);
        let toks: Vec<_> = r.iter().collect();

        assert!(toks[0].is_err());
        assert_eq!(
            toks[0].as_ref().err().unwrap(),
            &Error::BadKeyword(Pos::from_line(1, 1))
        );

        assert!(toks[1].is_ok());
        assert!(toks[1].is_ok_with_non_annotation());
        assert!(!toks[1].is_ok_with_annotation());
        assert!(toks[1].is_ok_with_kwd_in(&[APPLE, ORANGE]));
        assert!(toks[1].is_ok_with_kwd_not_in(&[ORANGE, UNRECOGNIZED]));
        let t = toks[1].as_ref().unwrap();
        assert_eq!(t.kwd(), APPLE);
        assert_eq!(t.arg(0), Some("3.14159"));

        assert!(toks[2].is_err());
        assert!(!toks[2].is_ok_with_non_annotation());
        assert!(!toks[2].is_ok_with_annotation());
        assert!(!toks[2].is_ok_with_kwd_in(&[APPLE, ORANGE]));
        assert!(!toks[2].is_ok_with_kwd_not_in(&[ORANGE, UNRECOGNIZED]));
        assert_eq!(
            toks[2].as_ref().err().unwrap(),
            &Error::BadKeyword(Pos::from_line(3, 1))
        );

        assert!(toks[3].is_ok());
        let t = toks[3].as_ref().unwrap();
        assert_eq!(t.kwd(), UNRECOGNIZED);
        assert_eq!(t.arg(1), Some("foo"));

        assert!(toks[4].is_err());
        assert_eq!(
            toks[4].as_ref().err().unwrap(),
            &Error::BadObjectMismatchedTag(Pos::from_line(8, 1))
        );

        assert!(toks[5].is_ok());
        let t = toks[5].as_ref().unwrap();
        assert_eq!(t.kwd(), ORANGE);
        assert_eq!(t.args_as_str(), "");

        // This blob counts as two errors: a bad base64 blob, and
        // then an end line.
        assert!(toks[6].is_err());
        assert_eq!(
            toks[6].as_ref().err().unwrap(),
            &Error::BadObjectBase64(Pos::from_line(12, 1))
        );

        assert!(toks[7].is_err());
        assert_eq!(
            toks[7].as_ref().err().unwrap(),
            &Error::BadKeyword(Pos::from_line(13, 1))
        );

        assert!(toks[8].is_ok());
        let t = toks[8].as_ref().unwrap();
        assert_eq!(t.kwd(), GUAVA);

        // this is an error because you can't use opt with annotations.
        assert!(toks[9].is_err());
        assert_eq!(
            toks[9].as_ref().err().unwrap(),
            &Error::BadKeyword(Pos::from_line(15, 1))
        );

        // this looks like a few errors.
        assert!(toks[10].is_err());
        assert_eq!(
            toks[10].as_ref().err().unwrap(),
            &Error::BadObjectBeginTag(Pos::from_line(17, 1))
        );
        assert!(toks[11].is_err());
        assert_eq!(
            toks[11].as_ref().err().unwrap(),
            &Error::BadKeyword(Pos::from_line(18, 1))
        );
        assert!(toks[12].is_err());
        assert_eq!(
            toks[12].as_ref().err().unwrap(),
            &Error::BadKeyword(Pos::from_line(19, 1))
        );

        // so does this.
        assert!(toks[13].is_err());
        assert_eq!(
            toks[13].as_ref().err().unwrap(),
            &Error::BadObjectBeginTag(Pos::from_line(21, 1))
        );
        assert!(toks[14].is_err());
        assert_eq!(
            toks[14].as_ref().err().unwrap(),
            &Error::BadKeyword(Pos::from_line(22, 1))
        );
        assert!(toks[15].is_err());
        assert_eq!(
            toks[15].as_ref().err().unwrap(),
            &Error::BadKeyword(Pos::from_line(23, 1))
        );

        // not this.
        assert!(toks[16].is_err());
        assert_eq!(
            toks[16].as_ref().err().unwrap(),
            &Error::BadObjectEndTag(Pos::from_line(27, 1))
        );

        assert!(toks[17].is_err());
        assert_eq!(
            toks[17].as_ref().err().unwrap(),
            &Error::BadKeyword(Pos::from_line(28, 1))
        );

        assert!(toks[18].is_err());
        assert_eq!(
            toks[18].as_ref().err().unwrap(),
            &Error::TruncatedLine(Pos::from_line(29, 15))
        );
    }
}
