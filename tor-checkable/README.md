# tor-checkable

Traits for wrapping up signed and/or time-bound objects

## Overview

Frequently (for testing reasons or otherwise), we want to ensure
that an object can only be used if a signature is valid, or if
some timestamp is recent enough.

As an example, consider a self-signed certificate. You can parse
it cheaply enough (and find its key by doing so), but you probably
want to make sure that nobody will use that certificate unless its
signature is correct and its timestamps are not expired.

With the tor-checkable crate, you can instead return an object
that represents the certificate in its unchecked state.  The
caller can access the certificate, but only after checking the
signature and the time.

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.
Many other crates in Arti depend on it, but it should be generally
useful outside of Arti.

### Design notes and alternatives

The types in this crate provide functions to return the underlying
objects without checking them.  This is very convenient for testing,
though you wouldn't want to do it in production code.  To prevent
mistakes, these functions all begin with the word `dangerously`.

Another approach you might take is to put signature and timeliness
checks inside your parsing function.  But if you do that, it will
get hard to test your code: you will only be able to parse
certificates that are valid when the parser is running.  And if
you want to test parsing a new kind of certificate, you'll need to
make sure to put a valid signature on it.  (And all of this
signature parsing will slow down any attempts to fuzz your
parser.)

You could have your parser take a flag to tell it whether to check
signatures and timeliness, but that could be error prone: if anybody
sets the flag wrong, they will skip doing the checks.

License: MIT OR Apache-2.0
