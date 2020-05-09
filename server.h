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
  ssh_bind sshbind;
};

#endif // _SERVER_H_
