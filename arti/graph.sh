#!/bin/bash

cargo deps --filter \
      --no-transitive-deps \
      --filter $(for d in ../*/; do echo $(basename $d); done) \
      --subgraph tor-client tor-dirmgr tor-circmgr tor-chanmgr tor-proto \
      --subgraph-name "Asynchronous Tor implementation" \
| dot -Tpng > g.png

### arti,caret,coverage,target,tor-bytes,tor-cell,tor-cert,tor-chanmgr,tor-checkable,tor-circmgr,tor-client,tor-config,tor-consdiff,tor-decompress,tor-dirclient,tor-dirmgr,tor-linkspec,tor-llcrypto,tor-netdir,tor-netdoc,tor-proto,tor-protover,tor-retry,tor-rtcompat,tor-socksproto \
