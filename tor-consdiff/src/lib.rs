use std::convert::TryInto;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

mod err;
pub use err::Error;

type Result<T> = std::result::Result<T, Error>;

#[cfg(any(test, fuzz, feature = "slow-diff-apply"))]
pub fn apply_diff_trivial<'a>(input: &'a str, diff: &'a str) -> Result<DiffResult<'a>> {
    let mut diff_lines = diff.lines();
    let (d1, d2) = parse_diff_header(&mut diff_lines)?;

    let mut diffable = DiffResult::from_str(input, d1, d2);

    for command in DiffCommandIter::new(diff_lines) {
        command?.apply_to(&mut diffable)?;
    }

    Ok(diffable)
}

pub fn apply_diff<'a>(
    input: &'a str,
    diff: &'a str,
    check_digest_in: Option<[u8; 32]>,
) -> Result<DiffResult<'a>> {
    let mut input = DiffResult::from_str(input, [0; 32], [0; 32]);

    let mut diff_lines = diff.lines();
    let (d1, d2) = parse_diff_header(&mut diff_lines)?;
    if let Some(d_want) = check_digest_in {
        if d1 != d_want {
            return Err(Error::CantApply("listed digest does not match document"));
        }
    }

    let mut output = DiffResult::new(d1, d2);

    let mut prev_command = None; // XXX move this check to DiffCommandIter?
    for command in DiffCommandIter::new(diff_lines) {
        let command = command?;
        if let Some(ref prev) = prev_command {
            if !command.precedes(prev) {
                return Err(Error::BadDiff("diff commands not listed in reverse order"));
            }
        }
        command.apply_transformation(&mut input, &mut output)?;

        prev_command = Some(command);
    }

    output.push_reversed(&input.lines[..]);

    output.lines.reverse();
    Ok(output)
}

fn parse_diff_header<'a, I>(iter: &mut I) -> Result<([u8; 32], [u8; 32])>
where
    I: Iterator<Item = &'a str>,
{
    let line1 = iter.next();
    if line1 != Some("network-status-diff-version 1") {
        return Err(Error::BadDiff("unrecognized or missing header"));
    }
    let line2 = iter.next();
    if line2.is_none() {
        return Err(Error::BadDiff("header truncated"));
    }
    let line2 = line2.unwrap();
    if !line2.starts_with("hash") {
        return Err(Error::BadDiff("missing 'hash' line"));
    }
    let elts: Vec<_> = line2.split_ascii_whitespace().collect();
    if elts.len() != 3 {
        return Err(Error::BadDiff("invalid 'hash' line"));
    }
    let d1 = hex::decode(elts[1])?;
    let d2 = hex::decode(elts[2])?;
    if d1.len() != 32 || d2.len() != 32 {
        return Err(Error::BadDiff("wrong digest lengths on 'hash' line"));
    }
    Ok((d1.try_into().unwrap(), d2.try_into().unwrap()))
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
    d_pre: [u8; 32],
    d_post: [u8; 32],
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
    #[cfg(any(test, fuzz, feature = "slow-diff-apply"))]
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

    fn following_lines(&self) -> Option<usize> {
        use DiffCommand::*;
        match self {
            Delete { high, .. } => Some(high + 1),
            DeleteToEnd { .. } => None,
            Replace { high, .. } => Some(high + 1),
            Insert { pos, .. } => Some(pos + 1),
        }
    }

    fn first_removed_line(&self) -> usize {
        use DiffCommand::*;
        match self {
            Delete { low, .. } => *low,
            DeleteToEnd { low } => *low,
            Replace { low, .. } => *low,
            Insert { pos, .. } => *pos + 1, // XXXX note.
        }
    }

    fn precedes(&self, other: &DiffCommand<'a>) -> bool {
        let their_beginning = other.first_removed_line();
        match self.following_lines() {
            Some(my_end) => my_end <= their_beginning,
            None => false,
        }
    }

    fn apply_transformation(
        &self,
        input: &mut DiffResult<'a>,
        output: &mut DiffResult<'a>,
    ) -> Result<()> {
        if let Some(succ) = self.following_lines() {
            if let Some(subslice) = input.lines.get(succ - 1..) {
                // Lines from `succ` onwards are unaffected.  Copy them.
                output.push_reversed(subslice);
            } else {
                // Oops, dubious line number.
                return Err(Error::CantApply(
                    "ending line number didn't correspond to document",
                ));
            }
        }

        if let Some(lines) = self.lines() {
            // These are the lines we're inserting.
            output.push_reversed(lines);
        }

        let remove = self.first_removed_line();
        if remove - 1 > input.lines.len() {
            return Err(Error::CantApply(
                "starting line number didn't correspond to document",
            ));
        }
        input.lines.truncate(remove - 1);

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
            return Err(Error::BadDiff("command too short"));
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
            (_, _, _) => return Err(Error::BadDiff("can't parse command line")),
        };

        if let Some(ref mut linebuf) = cmd.linebuf_mut() {
            loop {
                match iter.next() {
                    None => return Err(Error::BadDiff("unterminated block to insert")),
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
    fn from_str(s: &'a str, d_pre: [u8; 32], d_post: [u8; 32]) -> Self {
        // I'd like to use str::split_inclusive here, but that isn't stable yet
        // as of rust 1.48.

        let lines: Vec<_> = s.lines().collect();

        DiffResult {
            d_pre,
            d_post,
            lines,
        }
    }

    fn new(d_pre: [u8; 32], d_post: [u8; 32]) -> Self {
        DiffResult {
            d_pre,
            d_post,
            lines: Vec::new(),
        }
    }

    fn push_reversed(&mut self, lines: &[&'a str]) {
        self.lines.extend(lines.iter().rev())
    }

    #[cfg(any(test, fuzz, feature = "slow-diff-apply"))]
    fn remove_lines(&mut self, first: usize, last: usize) -> Result<()> {
        if first > self.lines.len() || last > self.lines.len() || first == 0 || last == 0 {
            Err(Error::CantApply("line out of range"))
        } else if first > last {
            Err(Error::BadDiff("mis-ordered lines in range"))
        } else {
            let n_to_remove = last - first + 1;
            if last != self.lines.len() {
                self.lines[..].copy_within((last).., first - 1);
            }
            self.lines.truncate(self.lines.len() - n_to_remove);
            Ok(())
        }
    }

    #[cfg(any(test, fuzz, feature = "slow-diff-apply"))]
    fn insert_at(&mut self, pos: usize, lines: &[&'a str]) -> Result<()> {
        if pos > self.lines.len() + 1 || pos == 0 {
            Err(Error::CantApply("position out of range"))
        } else {
            let orig_len = self.lines.len();
            self.lines.resize(self.lines.len() + lines.len(), "");
            self.lines
                .copy_within(pos - 1..orig_len, pos - 1 + lines.len());
            self.lines[(pos - 1)..(pos + lines.len() - 1)].copy_from_slice(lines);
            Ok(())
        }
    }
}

impl<'a> Display for DiffResult<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        for elt in self.lines.iter() {
            writeln!(f, "{}", elt)?
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn remove() -> Result<()> {
        let example = DiffResult::from_str("1\n2\n3\n4\n5\n6\n7\n8\n9\n", [0; 32], [0; 32]);

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
        let example = DiffResult::from_str("a\nb\nc\nd\ne\nf\n", [0; 32], [0; 32]);

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
