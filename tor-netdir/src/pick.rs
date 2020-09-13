/// Choose a nonuniform random member of an iterator.
///
/// For each value `v` yielded by `i`, this function will return that
/// value with probability proportional to `weightfn(v)`.
///
/// We'll return None if and only if there are no values with nonzero
/// weight.
// Performance note: this implementation requires a fast RNG, but
// doesn't need much storage.
pub fn pick_weighted<R, I, F>(rng: &mut R, i: I, weightfn: F) -> Option<I::Item>
where
    I: Iterator,
    F: Fn(&I::Item) -> u64,
    R: rand::Rng,
{
    let mut result = None;
    let mut weight_so_far: u64 = 0;

    // Correctness argument: at the end of each iteration of the loop,
    // `result` holds a value chosen with weighted probabability from
    // all of the items yielded so far.  The loop body preserves this
    // invariant.

    for item in i {
        let w = weightfn(&item);
        if w == 0 {
            continue;
        }
        // TODO: panics on overflow. Probably not best.
        weight_so_far = weight_so_far.checked_add(w).unwrap();

        let x = rng.gen_range(0, weight_so_far);
        // TODO: we could probably do this in constant-time, if we are
        // worried about a side-channel.
        if x < w {
            result = Some(item);
        }
    }

    result
}
