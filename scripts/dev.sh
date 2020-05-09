#!/bin/sh -ex
rm -rf .includes
mkdir -p .includes

docker create -it --name dummy sshforward-build bash
docker cp dummy:/usr/include/libssh/ .includes/
docker rm -f dummy

docker run --rm -it -v$PWD:/app \
       sshforward-build \
       make clean

docker run --rm -it -v$PWD:/app \
       --env CPPFLAGS="-I.includes -I." \
       --entrypoint bear \
       sshforward-dev \
       make
