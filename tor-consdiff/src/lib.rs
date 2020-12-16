#![allow(unused, dead_code)]

use std::num::ParseIntError;
use std::str::FromStr;

#[derive(Debug)]
pub enum Error {
    BadDiff,
    NoSuchLine,
    InvalidInt,
    CantParse,
}

type Result<T> = std::result::Result<T, Error>;

pub fn apply_diff<'a>(input: &'a str, diff: &'a str) -> Result<DiffResult<'a>> {
    let mut diffable = DiffResult::from_str(input);

    for command in DiffCommandIter::new(diff.lines()) {
        command?.apply_to(&mut diffable)?;
    }

    Ok(diffable)
}

impl From<ParseIntError> for Error {
    fn from(_e: ParseIntError) -> Error {
        Error::InvalidInt
    }
}

#[derive(Clone, Debug)]
enum DiffCommand<'a> {
    Delete {
        low: usize,
        high: usize,
    },
    DeleteToEnd {
        low: usize,
    },
    Replace {
        low: usize,
        high: usize,
        lines: Vec<&'a str>,
    }, // XXXX maybe slice
    Insert {
        pos: usize,
        lines: Vec<&'a str>,
    }, // XXXX maybe slice.
}

#[derive(Clone, Debug)]
pub struct DiffResult<'a> {
    lines: Vec<&'a str>,
}

#[derive(Clone, Debug)]
enum RangeEnd {
    Num(usize),
    DollarSign,
}

impl FromStr for RangeEnd {
    type Err = Error;
    fn from_str(s: &str) -> Result<RangeEnd> {
        if s == "$" {
            Ok(RangeEnd::DollarSign)
        } else {
            Ok(RangeEnd::Num(s.parse()?))
        }
    }
}

impl<'a> DiffCommand<'a> {
    fn apply_to(&self, target: &mut DiffResult<'a>) -> Result<()> {
        use DiffCommand::*;
        match self {
            Delete { low, high } => {
                target.remove_lines(*low, *high)?;
            }
            DeleteToEnd { low } => {
                target.remove_lines(*low, target.lines.len())?;
            }
            Replace { low, high, lines } => {
                target.remove_lines(*low, *high)?;
                target.insert_at(*low, lines)?;
            }
            Insert { pos, lines } => {
                // This '+1' seems off, but it's what the spec says. I wonder
                // if the spec is wrong.
                target.insert_at(*pos + 1, lines)?;
            } // TODO SPEC: In theory there is an 'InsertHere' command
              // that we should be implementing, but Tor doesn't use it.
        };
        Ok(())
    }

    fn lines(&self) -> Option<&[&'a str]> {
        use DiffCommand::*;
        match self {
            Replace { lines, .. } => Some(lines.as_slice()),
            Insert { lines, .. } => Some(lines.as_slice()),
            _ => None,
        }
    }

    fn linebuf_mut(&mut self) -> Option<&mut Vec<&'a str>> {
        use DiffCommand::*;
        match self {
            Replace { ref mut lines, .. } => Some(lines),
            Insert { ref mut lines, .. } => Some(lines),
            _ => None,
        }
    }

    fn from_line_iterator<I>(iter: &mut I) -> Result<Option<Self>>
    where
        I: Iterator<Item = &'a str>,
    {
        let command = match iter.next() {
            Some(s) => s,
            None => return Ok(None),
        };

        if command.len() < 2 || !command.is_ascii() {
            return Err(Error::CantParse);
        }

        let (range, command) = command.split_at(command.len() - 1);
        let (low, high) = if let Some(comma_pos) = range.find(',') {
            (
                range[..comma_pos].parse::<usize>()?,
                Some(range[comma_pos + 1..].parse::<RangeEnd>()?),
            )
        } else {
            (range.parse::<usize>()?, None)
        };

        use DiffCommand::*;

        let mut cmd = match (command, low, high) {
            ("d", low, None) => Delete { low, high: low },
            ("d", low, Some(RangeEnd::Num(high))) => Delete { low, high },
            ("d", low, Some(RangeEnd::DollarSign)) => DeleteToEnd { low },
            ("c", low, None) => Replace {
                low,
                high: low,
                lines: Vec::new(),
            },
            ("c", low, Some(RangeEnd::Num(high))) => Replace {
                low,
                high,
                lines: Vec::new(),
            },
            ("a", low, None) => Insert {
                pos: low,
                lines: Vec::new(),
            },
            (_, _, _) => return Err(Error::CantParse),
        };

        if let Some(ref mut linebuf) = cmd.linebuf_mut() {
            loop {
                match iter.next() {
                    None => return Err(Error::CantParse),
                    Some(".") => break,
                    Some(line) => linebuf.push(line),
                }
            }
        }

        Ok(Some(cmd))
    }
}

struct DiffCommandIter<'a, I>
where
    I: Iterator<Item = &'a str>,
{
    iter: I,
}

impl<'a, I> DiffCommandIter<'a, I>
where
    I: Iterator<Item = &'a str>,
{
    fn new(iter: I) -> Self {
        DiffCommandIter { iter }
    }
}

impl<'a, I> Iterator for DiffCommandIter<'a, I>
where
    I: Iterator<Item = &'a str>,
{
    type Item = Result<DiffCommand<'a>>;
    fn next(&mut self) -> Option<Result<DiffCommand<'a>>> {
        DiffCommand::from_line_iterator(&mut self.iter).transpose()
    }
}

impl<'a> DiffResult<'a> {
    pub fn from_str(s: &'a str) -> Self {
        // I'd like to use str::split_inclusive here, but that isn't stable yet
        // as of rust 1.48.

        let mut lines: Vec<_> = s.lines().collect();

        DiffResult { lines }
    }

    pub fn to_string(&self) -> String {
        let mut s = String::new();
        for elt in self.lines.iter() {
            s.push_str(elt);
            s.push('\n');
        }
        s
    }

    fn remove_lines(&mut self, first: usize, last: usize) -> Result<()> {
        if first > self.lines.len() || last > self.lines.len() || first == 0 || last == 0 {
            Err(Error::NoSuchLine)
        } else if first > last {
            Err(Error::BadDiff)
        } else {
            let n_to_remove = last - first + 1;
            if last != self.lines.len() {
                self.lines[..].copy_within((last).., first - 1);
            }
            self.lines.resize(self.lines.len() - n_to_remove, "");
            Ok(())
        }
    }

    fn insert_at(&mut self, pos: usize, lines: &[&'a str]) -> Result<()> {
        if pos > self.lines.len() + 1 || pos == 0 {
            Err(Error::NoSuchLine)
        } else {
            let orig_len = self.lines.len();
            self.lines.resize(self.lines.len() + lines.len(), "");
            self.lines
                .copy_within(pos - 1..orig_len, pos - 1 + lines.len());
            &self.lines[(pos - 1)..(pos + lines.len() - 1)].copy_from_slice(lines);
            Ok(())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn remove() -> Result<()> {
        let example = DiffResult::from_str("1\n2\n3\n4\n5\n6\n7\n8\n9\n");

        let mut d = example.clone();
        d.remove_lines(5, 7)?;
        assert_eq!(d.to_string(), "1\n2\n3\n4\n8\n9\n");

        let mut d = example.clone();
        d.remove_lines(1, 9)?;
        assert_eq!(d.to_string(), "");

        let mut d = example.clone();
        d.remove_lines(1, 1)?;
        assert_eq!(d.to_string(), "2\n3\n4\n5\n6\n7\n8\n9\n");

        let mut d = example.clone();
        d.remove_lines(6, 9)?;
        assert_eq!(d.to_string(), "1\n2\n3\n4\n5\n");

        let mut d = example.clone();
        assert!(d.remove_lines(6, 10).is_err());
        assert!(d.remove_lines(0, 1).is_err());
        assert_eq!(d.to_string(), "1\n2\n3\n4\n5\n6\n7\n8\n9\n");

        Ok(())
    }

    #[test]
    fn apply_command() {
        let example = DiffResult::from_str("a\nb\nc\nd\ne\nf\n");

        let mut d = example.clone();
        assert_eq!(d.to_string(), "a\nb\nc\nd\ne\nf\n".to_string());
        assert!(DiffCommand::DeleteToEnd { low: 5 }.apply_to(&mut d).is_ok());
        assert_eq!(d.to_string(), "a\nb\nc\nd\n".to_string());

        let mut d = example.clone();
        assert!(DiffCommand::Delete { low: 3, high: 5 }
            .apply_to(&mut d)
            .is_ok());
        assert_eq!(d.to_string(), "a\nb\nf\n".to_string());

        let mut d = example.clone();
        assert!(DiffCommand::Replace {
            low: 3,
            high: 5,
            lines: vec!["hello", "world"]
        }
        .apply_to(&mut d)
        .is_ok());
        assert_eq!(d.to_string(), "a\nb\nhello\nworld\nf\n".to_string());

        let mut d = example.clone();
        assert!(DiffCommand::Insert {
            pos: 3,
            lines: vec!["hello", "world"]
        }
        .apply_to(&mut d)
        .is_ok());
        assert_eq!(
            d.to_string(),
            "a\nb\nc\nhello\nworld\nd\ne\nf\n".to_string()
        );
    }

    #[test]
    fn parse_command() -> Result<()> {
        use DiffCommand::*;
        fn parse(s: &str) -> Result<DiffCommand> {
            let mut iter = s.lines();
            let cmd = DiffCommand::from_line_iterator(&mut iter)?;
            let cmd2 = DiffCommand::from_line_iterator(&mut iter)?;
            if cmd2.is_some() {
                panic!("Unexpected second command")
            }
            Ok(cmd.unwrap())
        }

        let p = parse("3,8d\n")?;
        assert!(matches!(p, Delete { low: 3, high: 8 }));
        let p = parse("3d\n")?;
        assert!(matches!(p, Delete { low: 3, high: 3 }));
        let p = parse("100,$d\n")?;
        assert!(matches!(p, DeleteToEnd { low: 100 }));

        let p = parse("30,40c\nHello\nWorld\n.\n")?;
        assert!(matches!(p, Replace{ low: 30, high: 40, .. }));
        assert_eq!(p.lines(), Some(&["Hello", "World"][..]));

        let p = parse("999a\nHello\nWorld\n.\n")?;
        assert!(matches!(p, Insert{ pos: 999, .. }));
        assert_eq!(p.lines(), Some(&["Hello", "World"][..]));

        Ok(())
    }
}
