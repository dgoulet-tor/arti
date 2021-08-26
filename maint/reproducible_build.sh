#!/bin/sh
set -xeu
if [ ! -f /.dockerenv ]; then
    echo Not running inside Docker, build will probably not be reproducible
	echo Use docker_reproducible_build.sh instead to get the right environment
fi
here=$(pwd)

## fix the target architecture to get reproducible builds
## the architecture was choosen as old enought that it should cover most usage
## while still supporting usefull features like AES-NI. Older architectures
## won't be able to execute the resulting binary.
export CFLAGS="-march=westmere"
export RUSTFLAGS="-C target-cpu=westmere"

## force build to run in a fixed location. Ncessesary because the build path
## is somehow captured when compiling.
cp -a "$here" /arti
cd /arti

## use tmpfs to store dependancies sources. It has been observed that what
## filesystem these files reside on has an impact on the resulting binary.
## We put these in a tmpfs as a way to stabilize the result.
# TODO CI /dev/shm is too small to store sources, at the moment we rely on
# a but in docker that gives a bigger than intended tmpfs in an effort to hide
# the cgroup control fs. This does not actually interact with cgroups, but
# should be removed as soon as /dev/shm get increased
if mount | grep '/sys/fs/cgroup type tmpfs' > /dev/null; then
		mkdir -p /sys/fs/cgroup/registry /usr/local/cargo/registry
		ln -s /sys/fs/cgroup/registry /usr/local/cargo/registry/src
else
		mkdir -p /dev/shm/registry /usr/local/cargo/registry
		ln -s /dev/shm/registry /usr/local/cargo/registry/src
fi

## add missing dependancies
apk add --no-cache musl-dev perl make git

## bring back the Cargo.lock where dependancies version are strictly defined
mv misc/Cargo.lock Cargo.lock

## Build targeting x86_64-unknown-linux-musl to get a static binary
## feature "static" enable compiling some C dependancies instead of linking
## to system libraries. It is required to get a well behaving result.
cargo build -p arti --target x86_64-unknown-linux-musl --release --features static

set +x
echo branch: "$(git rev-parse --abbrev-ref HEAD)"
echo commit: "$(git rev-parse HEAD)"
echo build hash: "$(sha256sum target/x86_64-unknown-linux-musl/release/arti | cut -d " " -f 1)"

mv /arti/target/x86_64-unknown-linux-musl/release/arti "$here"/arti-bin
