#!/bin/sh

BINARY=$1
if [ "$BINARY" = "simple" ]; then
	cd afl-protocol && rm -rf ../sample/simple/out && BIND_DIR=/tmp/ USE_SOCKFD=3 USE_SIGSTOP=1 ./afl-fuzz -i ../sample/simple/input_dir -o ../sample/simple/out -p 4000 -h ./libhook.so -t 10000  -- ../sample/simple/server 4000
fi
