# SSH-forward

Small application based on [libssh]. Accepts incoming ssh connections
for fixed user with public key authentication mode. Once the
connection is accepted instead of opening a shell it forwards the
channel to some other service.

## Usage

sshforward `<user>` `<pubkey>` `<host>` `<port>` [`<local port>`]

- user - username to accept
- pubkey - public key to authenticate
- host, port - where to forward to
- local port - where to listen (default 3000)

Server key used for authentication must be named `server.key` and
located in the working directory.

## Development

Docker containers are used for building/development/deployment.

### Containerfile.build

Can be used to build the application.

```sh
# build image
make image-build

# build application
docker run --rm -itP -v$(pwd):/app sshforward-build
```

### Containerfile.dev

Can be used for development.

```sh
# build image
make image-dev

# get libssh header files and generate compile_commads.json
./scripts/dev.sh

# run development container
docker run --rm -itP -v$(pwd):/app sshforward-dev
```

### Containerfile

Deploy the application.

```sh
make image-deploy
```

*FIXME: need to add files and supply arguments*


[libssh]: https://www.libssh.org/
