use subtle::*;

// Note that this doesn't necessarily do a constant-time comparison,
// and that it is not constant-time for found/not-found case.
pub fn lookup<'a, T, U, F>(item: &T, array: &'a [U], matches: F) -> Option<&'a U>
where
    F: Fn(&T, &U) -> Choice,
    T: ?Sized,
{
    // ConditionallySelectable isn't implemented for usize, so we need
    // to use u64.
    let mut idx: u64 = 0;
    let mut found: Choice = 0.into();

    for (i, x) in array.iter().enumerate() {
        let equal = matches(item, x);
        idx.conditional_assign(&(i as u64), equal);
        found.conditional_assign(&equal, equal)
    }

    if found.into() {
        Some(&array[idx as usize])
    } else {
        None
    }
}

pub fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    let choice = a.ct_eq(b);
    choice.unwrap_u8() == 1
}
