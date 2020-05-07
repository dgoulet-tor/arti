use crate::rules::*;
use crate::tokenize::*;
use crate::{Error, Position, Result};
use std::str::FromStr;

pub struct SectionRules<T: Keyword> {
    rules: Vec<Option<TokenFmt<T>>>,
}

#[derive(Clone)]
enum TokVal<'a> {
    None,
    Some([Item<'a>; 1]), // using a one-element array so we can slice it.
    Multi(Vec<Item<'a>>),
}
impl<'a> TokVal<'a> {
    fn count(&self) -> usize {
        match self {
            TokVal::None => 0,
            TokVal::Some(_) => 1,
            TokVal::Multi(v) => v.len(),
        }
    }
    fn first(&self) -> Option<&Item<'a>> {
        match self {
            TokVal::None => None,
            TokVal::Some([t]) => Some(t),
            TokVal::Multi(v) => Some(&v[0]),
        }
    }
    fn second(&self) -> Option<&Item<'a>> {
        match self {
            TokVal::Multi(v) if v.len() > 1 => Some(&v[1]),
            _ => None,
        }
    }
    fn singleton(&self) -> Option<&Item<'a>> {
        match self {
            TokVal::None => None,
            TokVal::Some([t]) => Some(t),
            TokVal::Multi(_) => None,
        }
    }
    fn as_slice(&self) -> &[Item<'a>] {
        match self {
            TokVal::None => &[],
            TokVal::Some(t) => &t[..],
            TokVal::Multi(v) => &v[..],
        }
    }
}

pub struct Section<'a, T: Keyword> {
    v: Vec<TokVal<'a>>,
    _t: std::marker::PhantomData<T>,
}

impl<'a, T: Keyword> Section<'a, T> {
    fn new() -> Self {
        let n = T::n_vals();
        let mut v = Vec::with_capacity(n);
        v.resize(n, TokVal::None);
        Section {
            v,
            _t: std::marker::PhantomData,
        }
    }
    fn get_tokval(&self, t: T) -> &TokVal<'a> {
        let idx = t.idx();
        &self.v[idx]
    }
    pub fn get_slice(&self, t: T) -> &[Item<'a>] {
        self.get_tokval(t).as_slice()
    }
    pub fn get(&self, t: T) -> Option<&Item<'a>> {
        self.get_tokval(t).singleton()
    }
    pub fn get_required(&self, t: T) -> Result<&Item<'a>> {
        self.get(t).ok_or(Error::Internal(Position::Unknown)) // XXXX
    }
    pub fn maybe<'b>(&'b self, t: T) -> MaybeItem<'b, 'a> {
        MaybeItem(self.get(t))
    }
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

// note: does not check multiplicity or absence.
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

fn item_matches_fmt_obj<'a, T: Keyword>(t: T, fmt: &TokenFmt<T>, item: &Item<'a>) -> Result<()> {
    match (&fmt.obj, item.has_obj()) {
        (ObjKind::NoObj, true) => Err(Error::UnexpectedObject(t.to_str(), item.pos())),
        (ObjKind::RequireObj, false) => Err(Error::MissingObject(t.to_str(), item.pos())),
        (_, _) => Ok(()),
    }
}
impl<T: Keyword> SectionRules<T> {
    pub fn new() -> Self {
        let n = T::n_vals();
        let mut rules = Vec::with_capacity(n);
        rules.resize(n, None);
        SectionRules { rules }
    }

    pub fn add(&mut self, t: TokenFmtBuilder<T>) {
        let idx = t.idx();
        self.rules[idx] = Some(t.into());
    }

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

        for (idx, (rule, t)) in self.rules.iter().zip(s.v.iter()).enumerate() {
            match rule {
                None => {
                    if t.count() > 0 {
                        let tokname = T::idx_to_str(idx);
                        return Err(Error::UnexpectedToken(tokname, t.second().unwrap().pos()));
                    }
                }
                Some(rule) => {
                    if t.count() == 0 && rule.required {
                        return Err(Error::MissingToken(T::idx_to_str(idx)));
                    } else if t.count() > 1 && !rule.may_repeat {
                        return Err(Error::DuplicateToken(
                            T::idx_to_str(idx),
                            t.second().unwrap().pos(),
                        ));
                    }
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

// because i can't add methods to Option<Item>
pub struct MaybeItem<'a, 'b>(Option<&'a Item<'b>>);

impl<'a, 'b> MaybeItem<'a, 'b> {
    pub fn parse_arg<V: FromStr>(&self, idx: usize) -> Result<Option<V>>
    where
        <V as FromStr>::Err: std::error::Error,
    {
        match self.0 {
            Some(item) => item.parse_arg(idx).map(Some),
            None => Ok(None),
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
