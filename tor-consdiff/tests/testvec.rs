#[test]
fn apply_tricky() {
    let pre = include_str!("../testdata/consensus1.txt");
    let diff = include_str!("../testdata/diff1.txt");
    let post = include_str!("../testdata/consensus2.txt");

    let result = tor_consdiff::apply_diff(pre, diff, None).unwrap();
    assert_eq!(result.to_string(), post);
}
