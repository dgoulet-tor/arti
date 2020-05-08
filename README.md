# arti: A Rust Tor Implementation

(I'm choosing this name for temporary purposes, but with a nod
to the fact that temporary names sometimes stick.  Its name is
a reference to Tor's semi-acronymic origins as "the onion
router", and to the Latin dative singular for "art".  It is
also short for "artifact".   It has nothing to do with the
"rt" issue tracker or the "rt" media outlet.)

## What's here and what isn't.

So far the code has untested or under-tested implementations of:
    * the ntor protocol
    * the relay crypto algorithm
    * parsing and encoding all the cell types (except for hs-related
       ones)
    * parsing and validating ed25519 certificates
    * parsing and validating router descriptors

Before I share it, I think it needs more work on:
    * parsing the other kinds of network documents
    * link authentication
    * a sensible api for cell types
    * a toy client that builds a circuit through the network
      and uses it to exit.

There is no support yet for:
    * Actually connecting to the network in a reasonable way
    * choosing paths through the network in a reasonable way
    * doing anything with the network in a reasonable way
    * actually building circuits
    * creating network documents
    * v2 onion service anything
    * v3 onion service anything
    * the directory protocol
    * lots of optimizations that Tor does
    * working with no_std

I do not plan to implement full versions of any of those before I
share this code for more comment, though I might do a little.  Who
knows?

## Caveat haxxor: what to watch out for

This is a work in progress.  It doesn't "do Tor" yet, and what parts
of Tor it does "do" it probably doesn't do securely.

I'm learning Rust here as I go along.  There are probably aspects of
the language or its ecosystem that I'm getting wrong.

Almost nothing about this code should be taken as "final" -- I
expect that if anybody wants to make this work for real purposes,
we'll need to refactor and move around a whole bunch of code, add a
bunch of APIs, split crates, merge crates, and so on.

There are some places where I am deviating from the existing
protocol under the assumption that certain proposals will be
accepted.  I'll try to document those.

This code does not try to be indistinguishable from the current Tor
implementation.

## Structure

To try to keep dependency relationships reasonable, and to follow
what I imagine to be best practice, I'm splitting this
implementation into a bunch of little crates within a workspace.
Crates that are tor-specific start with "tor-"; others don't.

I expect that the list of crates will have to be reorganized quite a
lot by the time we're done.

The current crates are:

caret
: A utility for generating enumerations with helpful trait
implementations

tor-llcrypto
: Wrappers and re-imports of cryptographic code that Tor needs in
various ways.  Other crates should use this crate, and not actually
use any crypto crates directly

tor-bytes
: Byte-by-byte encoder and decoder functions and traits.  We use
this to safely parse cells, certs, and other byte-oriented things.

tor-cert
: Decoding and checking signatures on Tor's ed25519 certificates.

tor-protover
: Minimal implementation of the Tor subprotocol verisoning system.
Less complete than the one in Tor's current src/rust, but more
simple.

tor-netdoc
: Parsing for Tor's network documents. Currently only handles
routerdescs.  Underdocumented and too big.  needs splitting.

tor-proto
: Functions to work with cell types, handshakes, and other aspects
of the Tor protocol.  Underdocumented, too big, needs
refactoring.


## Licence

As appears to be standard practice in the Rust ecosystem, this code is
licensed under either of

 * [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
 * [MIT license](http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

>(The above notice, or something like it, seems to be pretty standard in Rust
>projects, so I'm using it here too.  This instance of it is copied from
>the RustCrypto project's README.md file.)
