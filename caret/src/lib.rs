//! Crikey! Another Rust Enum Tool?
//!
//! This set of macros combines ideas from several other crates that
//! build C-like enums together with appropriate conversion functions to
//! convert to and from associated integers and associated constants.
//! It's inspired by features from enum_repr, num_enum, primitive_enum,
//! enum_primitive, enum_from_str, enum_str, enum-utils-from-str, and
//! numeric-enum-macro.  I'm not sure it will be useful to anybody but
//! me.
//!
//! To use it, write something like:
//!
//! ```
//! use caret::caret_enum;
//!
//! caret_enum! {
//!    pub enum EnumType as u16 {
//!       Variant1,
//!       Variant2,
//!       Variant3,
//!    }
//! }
//! ```
//!
//! When you define an enum using `caret_enum!`, it automatically gains
//! conversion methods:
//!     * to_int()
//!     * to_str(),
//!     * from_int(),
//!     * from_string().
//!
//! The macro will also implement several traits for you.
//!     * From<EnumType> for u16,
//!     * From<EnumType> for &str
//!     * Display for Enumtype
//!     * FromStr for EnumType
//!     * TryFrom<u16> for EnumType
//!
//! Finally, EnumType will have derived implementations for Eq,
//! PartialEq, Copy, and Clone, as you'd expect from a fancy alias for
//! u16.
//!
//! If you specify some other integer type instead of `u16`, that type
//! will be used as a representation instead.
//!
//! You can specify specific values for the enumerated elements:
//!
//! ```
//! # use caret::*;
//! # caret_enum!{ pub enum Example as u8 {
//!     Variant1 = 1,
//!     Variant2 = 5,
//!     Variant3 = 9,
//! # } }
//! ```
//!
//! You can also override the string representation for enumerated elements:
//! ```
//! # use caret::*;
//! # caret_enum!{ pub enum Example as u8 {
//!     Variant1 ("first"),
//!     Variant2 ("second"),
//!     Variant3 ("third") = 9,
//! # } }
//! ```

#[macro_export]
macro_rules! caret_enum {
    {
       $(#[$meta:meta])*
       $v:vis enum $name:ident as $numtype:ident {
           $(
               $(#[$item_meta:meta])*
               $id:ident $( ( $as_str:literal ) )? $( = $num:literal )?
           ),*
           $( , )?
      }
    } => {
        #[repr( $numtype )]
        #[derive(PartialEq,Eq,Copy,Clone)]
        $(#[$meta])*
        $v enum $name {
            $( $( #[$item_meta] )* $id $( = $num )? , )*
        }

        impl $name {
            pub fn to_int(self) -> $numtype {
                match self {
                    $( $name::$id => $name::$id as $numtype , )*
                }
            }
            pub fn to_str(self) -> &'static str {
                match self {
                    $( $name::$id => $crate::caret_enum!(@impl string_for $id $($as_str)?) , )*
                }
            }
            pub fn from_int(val: $numtype) -> Option<Self> {
                #![allow(non_upper_case_globals)]
                $( const $id : $numtype = $name::$id as $numtype; )*
                match val {
                    $( $id => Some($name::$id) , )*
                    _ => None
                }
            }
            fn from_string(val: &str) -> Option<Self> {
                match val {
                    $( $crate::caret_enum!(@impl string_for $id $($as_str)?) => Some($name::$id) , )*
                    _ => None
                }
            }
        }

        impl std::convert::From<$name> for $numtype {
            fn from(val: $name) -> $numtype {
                val.to_int()
            }
        }
        impl std::convert::From<$name> for &'static str {
            fn from(val: $name) -> &'static str {
                val.to_str()
            }
        }
        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.to_str())
            }
        }
        impl std::convert::TryFrom<$numtype> for $name {
            type Error = &'static str; // this is not the best error type XXXX
            fn try_from(val: $numtype) -> std::result::Result<Self, Self::Error> {
                $name::from_int(val).ok_or("Unrecognized value")
            }
        }
        impl std::str::FromStr for $name {
            type Err = &'static str; // this is not the best error type XXXX
            fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
                $name::from_string(s).ok_or("Unrecognized value")
            }
        }
    };

    // Internal helpers
    [ @impl string_for $id:ident $str:literal ] => ( $str );
    [ @impl string_for $id:ident ] => ( stringify!($id) );
}
