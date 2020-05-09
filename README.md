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

### Dockerfile.build

Can be used to build the application.

*FIXME: add usage example*

### Dockerfile.dev

Can be used for development.

```sh
docker build -t sshforward-dev -f Dockerfile.dev .
docker run --rm -itP -v$(pwd):/app sshforward-dev
```

To generate `compile_commands.json` run `make bear` then add
`-I<path to libssl headers>` and `-I.`.

*FIXME: find some way to automate this*

### Dockerfile

Deploy the application.

*FIXME: need to add files and supply arguments*


[libssh]: https://www.libssh.org/
