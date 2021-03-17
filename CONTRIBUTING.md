# Contributing

## Dogfooding

A good first step to start hacking on arti might be to hook it up with your Tor
Browser. Please note that arti is still a work in progress and hence you should
consider that it **provides no security** at the moment.

To do so, we will launch arti independently from Tor Browser. Build arti with
"cargo build --release" and after that launch it with some basic configuration parameters:

    $ ./target/release/arti -c "socks_port = 9150" -c "trace = false"

This will ensure that arti sets its SOCKS port on 9150. Now we need to launch
Tor Browser and instruct it to use that SOCKS port:

    $ TOR_SKIP_LAUNCH=1 TOR_SOCKS_PORT=9150 ./start-tor-browser.desktop

The resulting Tor Browser should be using arti.

Enjoy hacking on arti!
