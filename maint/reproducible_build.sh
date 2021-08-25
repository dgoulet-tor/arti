#!/bin/sh
set -x
if [ ! -f /.dockerenv ]; then
    echo Not running inside Docker, build will probably not be reproducible
	echo Use docker_reproducible_build.sh instead to get the right environment
fi
here=`pwd`

export CFLAGS="-march=westmere"
export RUSTFLAGS="-C target-cpu=westmere"

## force build to run in a fixed directory
cp -a $here /arti
cd /arti

## use tmpfs 
## TODO make /dev/shm bigger to not depend on a docker bug
#mkdir -p /dev/shm/registry /usr/local/cargo/registry
#ln -s /dev/shm/registry /usr/local/cargo/registry/src
mkdir -p /sys/fs/cgroup/registry /usr/local/cargo/registry
ln -s /sys/fs/cgroup/registry /usr/local/cargo/registry/src

## add missing dependancies
apk add --no-cache musl-dev perl make sqlite-static sqlite-dev

cargo build -p arti --target x86_64-unknown-linux-musl --release --features vendored
sha256sum target/x86_64-unknown-linux-musl/release/arti
