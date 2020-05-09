#ifndef _SERVER_H_
#define _SERVER_H_

#include <netdb.h>

#include <libssh/libssh.h>
#include <libssh/server.h>

struct forward_server_data {
  unsigned int port;
  struct addrinfo target;
  const char *username;
  ssh_key key;
};

struct forward_server {
  struct forward_server_data data;
  ssh_bind sshbind;
};

int setup_server(int argc, char *argv[], struct forward_server *server);

#endif // _SERVER_H_
