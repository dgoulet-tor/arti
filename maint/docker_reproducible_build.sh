#!/bin/sh
exec docker run --rm -i -v $(git rev-parse --show-toplevel):/builds/arti -w /builds/arti --shm-size=512m rust:1.54.0-alpine3.14 ./maint/reproducible_build.sh
