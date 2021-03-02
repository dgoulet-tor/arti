# arti: A Rust Tor Implementation

(I'm choosing this name for temporary purposes, but with a nod
to the fact that temporary names sometimes stick.  Its name is
a reference to Tor's semi-acronymic origins as "the onion
router", and to the Latin dative singular for "art".  It is
also short for "artifact".   It has nothing to do with the
"rt" issue tracker or the "rt" media outlet.)

## Is this the future of Tor??!?11?!?

It's not the future yet! ;)

I'm hoping that with time I can turn this code into a minimal Tor
client, and then we'll see what the situation is, and whether we should
keep on working on it.

There are absolutely no guarantees about stability.  Future versions of
Tor might break this; no users should expect source compatibility.

## What the demo can do if you run it.

It can act as a SOCKS proxy that uses the Tor network.  (Not a very
secure or anonymous one!)  It knows how to download directory
information and how to load it from cache, but it doesn't try to
download more than one directory per run.

To try it out, run the demo program in `tor-client`.   It will open a
SOCKS proxy on port 9150.

    % cargo run --release

Again, do not use this program if you need anonymity, privacy, security,
or stability.

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
  * a slightly wonky stream abstraction
  * Downloading and caching directory documents

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
  * Keeping directory documents up-to-date while running
  * Acting as a directory cache server
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

## Protocol support

Here's a checklist of Tor sub-protocol versions that we currently have
client-side support for:

  * [x] `Cons=2` [^1]
  * [x] `Desc=2`
  * [ ] `DirCache=2`
  * [x] `FlowCtrl=0`
  * [x] `FlowCtrl=1`
  * [ ] `HSDir=2`
  * [ ] `HSIntro=4` (maybe?)
  * [ ] `HSIntro=5`
  * [ ] `HSRend=2`
  * [x] `Link=4`
  * [ ] `Link=5`
  * [x] `Microdesc=2` [^1]
  * [ ] `Padding=2`
  * [x] `Relay=2`
  * [ ] `Relay=3` (not sure whether we're compliant with this client-side)

[^1]: If a consensus method before 28 is used, we won't find IPv6 addresses
correctly. All such consensus methods are currently obsolete, though, and
authorities won't negotiate them any more.

There is no relay-side support for anything right now. If there were, we'd
want to support:

  * [ ] `Cons=2`
  * [ ] `Desc=2`
  * [ ] `DirCache=2`
  * [ ] `FlowCtrl=0`
  * [ ] `FlowCtrl=1`
  * [ ] `HSDir=2`
  * [ ] `HSIntro=4` (maybe)
  * [ ] `HSIntro=5`
  * [ ] `HSRend=2`
  * [ ] `Link=4`
  * [ ] `Link=5`
  * [ ] `LinkAuth=3`
  * [ ] `Microdesc=2`
  * [ ] `Padding=2`
  * [ ] `Relay=2`
  * [ ] `Relay=3`

We do not ever plan to support these:

  * ❌ `Cons=1` (obsolete format)
  * ❌ `Desc=1` (obsolete format)
  * ❌ `DirCache=1` (no relays still support this)
  * ❌ `HSDir=2`
  * ❌ `HSIntro=3` (will be obsolete in 2021)
  * ❌ `HSRend=1` (will be obsolete in 2021)
  * ❌ `LinkAuth=1` (only used by RSA-only relays)
  * ❌ `Microdesc=1` (obsolete format)
  * ❌ `Padding=1` (deprecated)

We presume that these proposals will be accepted and merged into Tor:
  * [ ] 285 (Directory documents should be standardized as utf-8, tor#40131)
  * [ ] 315 (Make some directory fields "required", tor#40132)
  * [ ] 318 (Limit protovers to 0-63, tor#40133)

## What can I do with this?

You can build this all with `cargo build`.

You can run the tests, such as they are, with `cargo test`.

You can make documentation with `cargo doc`.  I prefer
`cargo doc --no-deps --document-private-items`, to include documentation for
private members but not for dependencies.

You can try running the demo SOCKS proxy code in `tor-client` with
`cargo run`.  Since rust builds code without optimization by default,
you'll probably want to say `cargo run --release`.

## I want to help. What _should_ I do with this?

Please check `CONTRIBUTING.md` for more dev related information.

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

`tor-llcrypto`: Wrappers and re-exports of cryptographic code that Tor needs in
various ways.  Other crates should use this crate, and not actually
use any crypto implementation crates directly.  (It's okay to use crates that
define cryptographic traits.)

`tor-rtcompat`: Wrappers and re-exports of asynchronous runtime
code. Currently it supports async-std and tokio.

`tor-bytes`: Byte-by-byte encoder and decoder functions and traits.  We use
this to safely parse cells, certs, and other byte-oriented things.

`tor-cert`: Decoding and checking signatures on Tor's ed25519 certificates.

`tor-protover`: Minimal implementation of the Tor subprotocol verisoning
system.  Less complete than the one in Tor's current src/rust, but more
simple.

`tor-socksproto`: Implements the server side of the SOCKS protocol, along
with Tor-specific extensions.

`tor-checkable`: Defines traits and types used to represent things that you
can't use until verifying their signatures and checking their timeliness.

`tor-consdiff`: Implements the client side of Tor's consensus-diff algorithm.

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
directories.

`tor-chanmgr`: Creates channels as necessary, returning existing channels
when they already exist.

`tor-circmgr`: Creates circuits as requested, returning existing circuits
when they already exist.

`tor-dirclient`: Downloads directory information over a one-hop circuit.

`tor-dirmgr`: Uses `tor-dirclient` to fetch directory information as needed
to download, cache, and maintain an up-to-date network view. Exposes the
network view as an instance of `tor-netdir::NetDir`.

`tor-client`: A client library that can be used to connect to the Tor network
and make connections.  Also comes with a a simple Tor client program that run
a SOCKS proxy.

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
