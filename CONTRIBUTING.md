# Contributing to Arti

We welcome new contributors!  You can get in contact with us on
[our gitlab instance](https://gitlab.torproject.org/), or on the
[`\#tor-dev IRC` channel on OFTC](https://www.torproject.org/contact/).
Make sure to familiarize yourself with our
[Code of Conduct](https://gitweb.torproject.org/community/policies.git/plain/code_of_conduct.txt).

The new-account process on our gitlab instance is moderated, to reduce
spam and abuse.  (*Insert instructions for anonymous usage here*)

## Licensing notice

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

## Using Arti with Torbrowser

A good first step to start hacking on arti might be to hook it up with your
Tor Browser. Please note that arti is still a work in progress and hence you
should assume that it **provides no security** at the moment.

To do so, we will launch arti independently from Tor Browser. Build arti with
`cargo build --release`.  After that launch it with some basic
configuration parameters:

    $ ./target/release/arti -c "socks_port = 9150" -c "trace = false"

This will ensure that arti sets its SOCKS port on 9150. Now we need to launch
Tor Browser and instruct it to use that SOCKS port:

    $ TOR_SKIP_LAUNCH=1 TOR_SOCKS_PORT=9150 ./start-tor-browser.desktop

The resulting Tor Browser should be using arti.  Note that onion services
won't work (Arti doesn't have them yet), and neither will any feature
depending on Tor's control-port protocol.

Enjoy hacking on arti!

## Where are some good places to start hacking?

You might want to begin by looking around the
[codebase](https://gitlab.torproject.org/tpo/core/arti/), or getting to
know our [architecture](./doc/Architecture.md).

More tests would always be great.

Parsing more Tor document types would be neat.

More documentation examples would be great.

Improvements or bugfixes to the existing code would be great.

Improving the look and feel of the documentation would also rock.

I've made a bunch of notes throughout the document in comments with strings
like "XXX" or "TODO".

There is a list of features that I wish other crates had in a file called
`WANT_FROM_OTHER_CRATES`.

Finally, check out
[the bugtracker](https://gitlab.torproject.org/tpo/core/arti/-/issues).
There are some tickets there labeled as
["First Contribution"](https://gitlab.torproject.org/tpo/core/arti/-/issues?scope=all&utf8=%E2%9C%93&state=opened&label_name[]=First%20Contribution):
that label means that we think they might be a good place to start out.

## Caveat haxxor: what to watch out for

Please don't assume that what you see here is good Rust: we've tried to
follow best practices, but we've been learning Rust here as we go along.
There are probably aspects of the language or its ecosystem that we're
getting wrong.

Almost nothing about this code should be taken as "final" -- I expect
that we'll need to refactor and move around a whole bunch of code, add a
bunch of APIs, split crates, merge crates, and so on.

There are some places where I am deviating from the existing Tor
protocol under the assumption that certain proposals will be
accepted.  See [Compatibility.md](./doc/Compatibility.md) for more
information.

This code does not attempt to be indistinguishable from the current Tor
implementation.

