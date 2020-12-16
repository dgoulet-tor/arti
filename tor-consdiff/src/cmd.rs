
enum DiffCommand<'a> {
    Delete { low: usize, high: usize },
    DeleteToEnd { low: usize },
    Replace { low: usize, high: usize, block: &'a str },
    Insert { pos: usize, block: &'a str },
    // InsertHere { block: &'a str },
}
