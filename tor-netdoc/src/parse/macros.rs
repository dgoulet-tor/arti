/// Macro for declaring a keyword enumeration to help parse a document.
///
/// A keyword enumber implements the Keyword trait.
///
/// These enums are a bit different from those made by `caret`, in a
/// few ways.  Notably, they are optimized for parsing, they are
/// required to be compact, and they allow multiple strings to be mapped to
/// a single index.
///
/// ```ignore
/// decl_keyword! {
///    Location {
//         "start" => START,
///        "middle" | "center" => MID,
///        "end" => END
///    }
/// }
///
/// assert_eq!(Location::from_str("start"), Location::START);
/// assert_eq!(Location::from_str("stfff"), Location::UNRECOGNIZED);
/// ```
macro_rules! decl_keyword {
    { $(#[$meta:meta])* $v:vis
      $name:ident { $( $($anno:ident)? $($s:literal)|+ => $i:ident),* $(,)? } } => {
        #[derive(Copy,Clone,Eq,PartialEq,Debug,std::hash::Hash)]
        #[allow(non_camel_case_types)]
        $(#[$meta])*
        $v enum $name {
            $( $i , )*
            UNRECOGNIZED,
            ANN_UNRECOGNIZED
        }
        impl $crate::parse::keyword::Keyword for $name {
            fn idx(self) -> usize { self as usize }
            fn n_vals() -> usize { ($name::ANN_UNRECOGNIZED as usize) + 1 }
            fn from_str(s : &str) -> Self {
                // Note usage of phf crate to create a perfect hash over
                // the possible keywords.  It will be even better if someday
                // the phf crate can find hash functions that are better
                // than siphash.
                const KEYWORD: phf::Map<&'static str, $name> = phf::phf_map! {
                    $( $( $s => $name::$i , )+ )*
                };
                match KEYWORD.get(s) {
                    Some(k) => *k,
                    None => if s.starts_with('@') {
                        $name::ANN_UNRECOGNIZED
                    } else {
                        $name::UNRECOGNIZED
                    }
                }
            }
            fn from_idx(i : usize) -> Option<Self> {
                // Note looking up the value in a vec.  This may or may
                // not be faster than a case statement would be.
                lazy_static::lazy_static! {
                    static ref VALS: Vec<$name> =
                        vec![ $($name::$i , )*
                              $name::UNRECOGNIZED,
                              $name::ANN_UNRECOGNIZED ];
                };
                VALS.get(i).copied()
            }
            fn to_str(self) -> &'static str {
                use $name::*;
                match self {
                    // TODO: this turns "accept" | "reject" into
                    // "acceptreject", which is not great.
                    // "accept/reject" would be better.
                    $( $i => concat!{ $($s),+ } , )*
                    UNRECOGNIZED => "<unrecognized>",
                    ANN_UNRECOGNIZED => "<unrecognized annotation>"
                }
            }
            fn is_annotation(self) -> bool {
                use $name::*;
                match self {
                    $( $i => decl_keyword![@impl is_anno $($anno)? ], )*
                    UNRECOGNIZED => false,
                    ANN_UNRECOGNIZED => true,
                }
            }
        }
    };
    [ @impl is_anno annotation ] => ( true );
    [ @impl is_anno $x:ident ] => ( compile_error!("unrecognized keyword; not annotation") );
    [ @impl is_anno ] => ( false );
}
