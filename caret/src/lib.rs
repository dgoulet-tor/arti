//! # Crikey! Another Rust Enum Tool?
//!
//! A macro to implement string and int conversions for c-like enums.
//!
//! This crate defines a `caret_enum!` macro, that lets you describe
//! "c-like" enumerations (ones with no data, only discriminators). It then
//! then automatically builds functions to convert those enums to
//! and from integer types, and to and from strings.
//!
//! To use it, write something like:
//!
//! ```
//! use caret::caret_enum;
//!
//! caret_enum! {
//!     #[derive(Debug)]
//!     pub enum Fruit as u16 {
//!         Peach = 1,
//!         Pear,
//!         Plum,
//!    }
//! }
//! ```
//!
//! When you define an enum using `caret_enum!`, it automatically gains
//! conversion methods:
//!
//! ```
//! # use caret::caret_enum;
//! # caret_enum! { #[derive(Debug)]
//! #    pub enum Fruit as u16 {
//! #    Peach = 1, Pear, Plum
//! # } }
//! assert_eq!(Fruit::Peach.to_int(), 1);
//! assert_eq!(Fruit::Pear.to_str(), "Pear");
//! assert_eq!(Fruit::from_int(1), Some(Fruit::Peach));
//! assert_eq!(Fruit::from_string("Plum"), Some(Fruit::Plum));
//! ```
//!
//! The `caret_enum!` macro will also implement several traits for you:
//!
//! ```
//! # use caret::caret_enum;
//! # caret_enum! { #[derive(Debug)]
//! #    pub enum Fruit as u16 {
//! #    Peach = 1, Pear, Plum
//! # } }
//! // impl From<Fruit> for u16
//! let val: u16 = Fruit::Peach.into();
//! assert_eq!(val, 1u16);
//!
//! // impl From<Fruit> for &str
//! let val: &str = Fruit::Plum.into();
//! assert_eq!(val, "Plum");
//!
//! // impl Display for Fruit
//! assert_eq!(format!("I need a recipe for a {} pie", Fruit::Peach),
//!            "I need a recipe for a Peach pie");
//!
//! // impl TryFrom<u16> for Fruit
//! use std::convert::TryInto;
//! let fruit: Fruit = 3u16.try_into().unwrap();
//! assert_eq!(fruit, Fruit::Plum);
//!
//! // impl FromStr for Fruit
//! let fruit: Fruit = "Pear".parse().unwrap();
//! assert_eq!(fruit, Fruit::Pear);
//! ```
//!
//! Finally, the enumeration will have derived implementations for Eq,
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
//! caret_enum!{
//!     #[derive(Debug)]
//!     pub enum Fruit as u8 {
//!         Peach = 1,
//!         Pear = 5,
//!         Plum = 9,
//!     }
//! }
//!
//! assert_eq!(Fruit::from_int(5), Some(Fruit::Pear));
//! ```
//!
//! ## Advanced features
//!
//! You can also override the string representation for enumerated elements:
//! ```
//! # use caret::*;
//! caret_enum!{
//!     #[derive(Debug)]
//!     pub enum Fruit as u8 {
//!        Peach ("donut"),
//!        Pear ("anjou"),
//!        Plum ("mirabelle") = 9,
//!     }
//! }
//!
//! let fruit: Fruit = "mirabelle".parse().unwrap();
//! assert_eq!(fruit, Fruit::Plum);
//! ```
//! ## Ackowledgments
//!
//! This crate combines ideas from several other crates that
//! build C-like enums together with appropriate conversion functions to
//! convert to and from associated integers and associated constants.
//! It's inspired by features from enum_repr, num_enum, primitive_enum,
//! enum_primitive, enum_from_str, enum_str, enum-utils-from-str, and
//! numeric-enum-macro.  I'm not sure it will be useful to anybody but
//! me.

#![deny(missing_docs)]

/// Declare a c-like enumeration, and implement conversion traits.
///
/// See module-level documentation.
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
            /// Convert an instance of this enumeration to an integer.
            ///
            /// (implemented by caret_enum!)
            pub fn to_int(self) -> $numtype {
                match self {
                    $( $name::$id => $name::$id as $numtype , )*
                }
            }
            /// Convert an instance of this enumeration object to a string.
            ///
            /// (implemented by caret_enum!)
            pub fn to_str(self) -> &'static str {
                match self {
                    $( $name::$id => $crate::caret_enum!(@impl string_for $id $($as_str)?) , )*
                }
            }
            /// Convert an integer to an instance of this enumeration.
            ///
            /// If the provided integer does not represent an instance
            /// of this enumeration, return None.
            pub fn from_int(val: $numtype) -> Option<Self> {
                #![allow(non_upper_case_globals)]
                $( const $id : $numtype = $name::$id as $numtype; )*
                match val {
                    $( $id => Some($name::$id) , )*
                    _ => None
                }
            }
            /// Convert a string to an instance of this enumeration.
            ///
            /// If the provided string does not represent an instance
            /// of this enumeration, return None.
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
