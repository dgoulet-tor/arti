# tor-chanmgr

`tor-chanmgr`: Manage a set of channels on the Tor network.

## Overview

This crate is part of
[Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
implement [Tor](https://www.torproject.org/) in Rust.

In Tor, a channel is a connection to a Tor relay.  It can be
direct via TLS, or indirect via TLS over a pluggable transport.
(For now, only direct channels are supported.)

Since a channel can be used for more than one circuit, it's
important to reuse channels when possible.  This crate implements
a [`ChanMgr`] type that can be used to create channels on demand,
and return existing channels when they already exist.

License: MIT OR Apache-2.0
