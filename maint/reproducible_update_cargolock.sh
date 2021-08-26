#!/bin/sh
#
# Update the misc/Cargo.lock file that we use for reproducible builds.
#
set -e
cd "$(git rev-parse --show-toplevel)"
mv Cargo.lock Cargo.lock.back 2> /dev/null || true
cargo update
mv Cargo.lock misc/
mv Cargo.lock.back Cargo.lock 2> /dev/null || true
