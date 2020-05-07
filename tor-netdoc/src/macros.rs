macro_rules! decl_keyword {
    { $name:ident { $( $($s:literal)|+ => $i:ident),* $(,)? } } => {
        #[derive(Copy,Clone,Eq,PartialEq,Debug,std::hash::Hash)]
        #[allow(non_camel_case_types)]
        pub enum $name {
            $( $i , )*
            UNRECOGNIZED
        }
        impl $crate::rules::Keyword for $name {
            fn idx(self) -> usize { self as usize }
            fn n_vals() -> usize { ($name::UNRECOGNIZED as usize) + 1 }
            fn from_str(s : &str) -> Self {
                const KEYWORD: phf::Map<&'static str, $name> = phf::phf_map! {
                    $( $( $s => $name::$i , )+ )*
                };
                * KEYWORD.get(s).unwrap_or(& $name::UNRECOGNIZED)
            }
            fn from_idx(i : usize) -> Option<Self> {
                lazy_static::lazy_static! {
                    static ref VALS: Vec<$name> =
                        vec![ $($name::$i , )* $name::UNRECOGNIZED ];
                };
                VALS.get(i).copied()
            }
            fn to_str(&self) -> &'static str {
                use $name::*;
                match self {
                    $( $i => concat!{ $($s),+ } , )*
                    UNRECOGNIZED => "<unrecognized>"
                }
            }
        }
        impl $name {
            pub fn rule(self) -> $crate::rules::TokenFmtBuilder<Self> {
                $crate::rules::TokenFmtBuilder::new(self)
            }
        }
    }
}
