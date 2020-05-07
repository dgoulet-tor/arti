use caret::caret_enum;
use std::convert::TryInto;

caret_enum! {
    #[derive(Debug)]
    enum Demo as u16 {
        A = 8,
        B ("TheLetterB") = 10,
        C,
        Dee = 999,
    }
}

#[test]
fn test_int_ops() {
    assert_eq!(Demo::A.to_int(), 8u16);
    assert_eq!(Demo::B.to_int(), 10);
    assert_eq!(Demo::C.to_int(), 11);
    assert_eq!(Demo::Dee.to_int(), 999);

    let t: u16 = Demo::A.into();
    assert_eq!(t, 8);

    let t: Demo = 999.try_into().unwrap();
    assert_eq!(t, Demo::Dee);
    assert_eq!(Demo::from_int(11), Some(Demo::C));

    assert_eq!(Demo::from_int(2), None);
    let t: Result<Demo, _> = 6.try_into();
    assert!(t.is_err());
}

#[test]
fn test_str_ops() {
    assert_eq!(Demo::A.to_str(), "A");
    assert_eq!(Demo::B.to_str(), "TheLetterB");
    let t: &str = Demo::C.into();
    assert_eq!(t, "C");
    assert_eq!(format!("Hello {}", Demo::Dee), "Hello Dee");

    let t: Demo = "TheLetterB".parse().unwrap();
    assert_eq!(t, Demo::B);
    let t: Result<Demo, _> = "XYZ".parse();
    assert!(t.is_err());
    let t: Demo = "Dee".parse().unwrap();
    assert_eq!(t, Demo::Dee);
    let t: Result<Demo, _> = "Foo".parse();
    assert!(t.is_err());
}
