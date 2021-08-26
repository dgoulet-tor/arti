#!/bin/sh
## use a fixed image to not suffer from image retaging when newer rustc or
## alpine emerges. Increase shm size for the reasons described in
## reproducible_build.sh
exec docker run --rm -i -v "$(git rev-parse --show-toplevel)":/builds/arti \
		-w /builds/arti --shm-size=512m rust:1.54.0-alpine3.14 \
		./maint/reproducible_build.sh
