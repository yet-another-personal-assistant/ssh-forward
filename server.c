#include <stdio.h>

#include "server.h"
#include "utils.h"

int setup_server(int argc, char *argv[], struct forward_server *server) {
  unsigned int port;
  if (parse_args(argc, argv, &server->data, &port) == -1)
    return -1;

  server->sshbind = ssh_bind_new();
  if (server->sshbind == NULL) {
    perror("ssh bind new");
    return -1;
  }
  if (ssh_bind_options_set(server->sshbind, SSH_BIND_OPTIONS_RSAKEY,
                           "server.key") == SSH_ERROR) {
    printf("ssh bind set rsakey error: %s\n", ssh_get_error(server->sshbind));
    return -1;
  }
  if (ssh_bind_options_set(server->sshbind, SSH_BIND_OPTIONS_BINDPORT, &port) ==
      SSH_ERROR) {
    printf("ssh bind set port error: %s\n", ssh_get_error(server->sshbind));
    return -1;
  }
  return 0;
}
