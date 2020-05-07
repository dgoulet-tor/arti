use crate::{Error, Position, Result};
use std::cell::{Ref, RefCell};
use std::str::FromStr;

#[derive(Clone, Copy, Debug)]
pub struct Object<'a> {
    tag: &'a str,
    data: &'a str, // not yet guaranteed to be base64.
}

#[derive(Clone, Debug)]
pub struct Item<'a> {
    pub off: usize, // don't make this pub.XXXX
    kwd: &'a str,
    args: &'a str,
    split_args: RefCell<Option<Vec<&'a str>>>,
    object: Option<Object<'a>>,
}

#[derive(Clone, Debug)]
pub struct NetDocReader<'a> {
    s: &'a str,
    off: usize,
}

impl<'a> NetDocReader<'a> {
    pub fn new(s: &'a str) -> Self {
        NetDocReader { s, off: 0 }
    }
    fn get_pos(&self, pos: usize) -> Position {
        Position::from_offset(self.s, pos)
    }
    fn advance(&mut self, n: usize) -> Result<()> {
        if n > self.remaining() {
            return Err(Error::Internal(Position::from_offset(self.s, self.off)));
        }
        self.off += n;
        Ok(())
    }
    fn remaining(&self) -> usize {
        self.s.len() - self.off
    }

    fn starts_with(&self, s: &str) -> bool {
        self.s[self.off..].starts_with(s)
    }
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

impl<'a> Iterator for NetDocReader<'a> {
    type Item = Result<Item<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        self.get_item().transpose()
    }
}

fn base64_decode_multiline(s: &str) -> std::result::Result<Vec<u8>, base64::DecodeError> {
    // base64 module hates whitespace.
    let mut v = Vec::new();
    for line in s.lines() {
        base64::decode_config_buf(line.trim_end(), base64::STANDARD, &mut v)?;
    }
    Ok(v)
}

impl<'a> Item<'a> {
    pub fn get_pos_in(&self, s: &'a str) -> Position {
        Position::from_offset(s, self.off)
    }
    pub fn get_kwd(&self) -> &'a str {
        self.kwd
    }
    pub fn args_as_str(&self) -> &'a str {
        self.args
    }
    pub fn args_as_vec(&self) -> Ref<Vec<&'a str>> {
        if self.split_args.borrow().is_none() {
            self.split_args.replace(Some(self.args().collect()));
        }
        Ref::map(self.split_args.borrow(), |opt| match opt {
            Some(v) => v,
            None => panic!(),
        })
    }
    pub fn args(&self) -> impl Iterator<Item = &'a str> {
        fn is_sp(c: char) -> bool {
            c == ' ' || c == '\t'
        }
        self.args.split(is_sp).filter(|s| !s.is_empty())
    }
    pub fn get_arg(&self, idx: usize) -> Option<&'a str> {
        self.args_as_vec().get(idx).copied()
    }
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
    pub fn n_args(&self) -> usize {
        self.args().count()
    }
    pub fn has_obj(&self) -> bool {
        self.object.is_some()
    }
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
    pub fn pos(&self) -> Position {
        Position::from_byte(self.off)
    }
    pub fn pos_in(&self, s: &str) -> Position {
        Position::from_offset(s, self.off)
    }
}
