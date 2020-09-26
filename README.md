# arti: A Rust Tor Implementation

(I'm choosing this name for temporary purposes, but with a nod
to the fact that temporary names sometimes stick.  Its name is
a reference to Tor's semi-acronymic origins as "the onion
router", and to the Latin dative singular for "art".  It is
also short for "artifact".   It has nothing to do with the
"rt" issue tracker or the "rt" media outlet.)

## Is this the future of Tor??!?11?!?

No, this is a fun side project I'm doing on weekends to learn Rust.

Maybe if it turns out great we can turn it into something official,
but right now nobody's working on it but me, and I'm not working on
it seriously at all.

## What the demo can do if you run it.

There is a demo program that looks for a chutney directory in
~/src/chutney/net/nodes/. If it finds one, it reads the directory info from
disk, builds a random three hop circuit, and sends a request for
http://www.torproject.org:80/.  Then it displays the answer.

## What's here and what isn't.

So far the code has untested or under-tested implementations of:

  * the ntor protocol
  * the relay crypto algorithm
  * parsing and encoding all the cell types (except for hs-related
       ones)
  * parsing and validating ed25519 certificates
  * parsing and validating router descriptors
  * parsing and validating microdescriptors
  * parsing and validating microdesc consensuses
  * link authentication (client->server type)
  * building circuits from chosen hops
  * a slightly wonky circuit abstraction
  * a slightly stream abstraction

Before I share it more broadly, I think it needs more work on:

  * refactoring everywhere
  * cleanup everywhere
  * lots of tests
  * a better api for cell types
  * better APIs for anything that needs to get exposed

There is no support yet for:

  * Actually connecting to the network in a reasonable way
  * choosing paths through the network in a reasonable way
  * doing anything with the network in a reasonable way
  * creating network documents
  * v2 onion service anything
  * v3 onion service anything
  * the directory protocol (downloading or uploading)
  * lots of optimizations that Tor does
  * lots of security stuff that Tor does
  * pluggable transports
  * bridges
  * working with no_std, at all.
  * being a relay
  * disabling unused code
  * rate limiting
  * API stability

I do not plan to implement full versions of any of those before I
share this code for more comment, though I might do a little.  Who
knows?

## What can I do with this?

You can build this all with `cargo build`.

You can run the tests, such as they are, with `cargo test`.

You can make documentation with `cargo doc`.  I prefer
`cargo doc --no-deps --document-private-items`, to include documentation for
private members but not for dependencies.

You can try running the demo code in `client-demo` with `cd client-demo &&
cargo run`.  You'll need to have a running local chutney network first; see
the documentation for that program.

## I want to help. What _should_ I do with this?

More tests would be great.

Parsing more document types would be neat.

More documentation examples would be great.

Improvements or bugfixes to the existing code would be great.

Improving the look and feel of the documentation would also rock.

I've made a bunch of notes throughout the document in comments with strings
like "XXX" or "TODO".

There is a list of features that I wish other crates had in
`WANT_FROM_OTHER_CRATES`.

Please hold off on opening tickets unless you are pretty sure that you're
reporting a problem I don't know about. :)


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

`caret`: A utility for generating enumerations with helpful trait
implementations

`tor-llcrypto`: Wrappers and re-imports of cryptographic code that Tor needs in
various ways.  Other crates should use this crate, and not actually
use any crypto crates directly.

`tor-bytes`: Byte-by-byte encoder and decoder functions and traits.  We use
this to safely parse cells, certs, and other byte-oriented things.

`tor-cert`: Decoding and checking signatures on Tor's ed25519 certificates.

`tor-protover`: Minimal implementation of the Tor subprotocol verisoning
system.  Less complete than the one in Tor's current src/rust, but more
simple.

`tor-netdoc`: Parsing for Tor's network documents.  Underdocumented and too
big.

`tor-linkspec`: Traits and types for connecting and extending to Tor relays.

`tor-cell`: Encoding and decoding for Tor cells.

`tor-proto`: Functions to work with handshakes, channels, circuits, streams,
and other aspects of the Tor protocol.  This crate is NOT ALLOWED to have any
dependencies on specific TLS libraries or specific async environments; those
have to happen at a higher level.  (Perhaps this crate should be split into a
cell handling API and a network API.  The division point would fairly
logical.)

`tor-netdir`: Wraps tor-netdoc to expose a "tor network directory" interface.
Doesn't touch the network itself.  Right now it only handles microdesc-based
directories, and reads all its information from disk.

`client-demo`: A simple tor client program.  Right now it requires that you
already have a datadir full of directory information.  It does a client->relay
handshake, builds a three-hop circuit, fetches http://www.torproject.org:80/,
and exits.

## Intended architecture

I'm hoping to have small, optional, separable pieces here.  For everything
I'm writing, I'm hoping it can go behind a configuration flag.

I'm also hoping to focus on everything that _isn't_ the network first.  I'd
like as little code as possible to actually read and write to the network,
and as much code as possible to pretend that the network doesn't exist.  I
hope this will make everything easier to test.

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
