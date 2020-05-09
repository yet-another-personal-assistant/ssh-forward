#include <stdio.h>
#include <stdlib.h>

#include <libssh/server.h>

#include "server.h"
#include "session.h"


int main(int argc, char *argv[]) {
  ssh_set_log_level(SSH_LOG_TRACE);

  struct forward_server server;
  if (setup_server(argc, argv, &server) == -1)
    goto out;

  _ssh_log(SSH_LOG_TRACE, "main", "Server is set up");

  if (ssh_bind_listen(server.sshbind) == SSH_ERROR) {
    printf("ssh bind listen error: %s\n", ssh_get_error(server.sshbind));
    goto out;
  }

  _ssh_log(SSH_LOG_TRACE, "main", "Server is listening");

  ssh_session session = ssh_new();
  while (1) {
    if (ssh_bind_accept(server.sshbind, session) == SSH_ERROR) {
      printf("Failed to accept connection: %s\n",
             ssh_get_error(server.sshbind));
      break;
    }
    switch (fork()) {
    case -1:
      perror("fork");
      goto out;
    case 0:
      exit(handle_session(session, &server.data));
    default:
      break;
    }
  }

out:
  if (server.sshbind != NULL)
    ssh_bind_free(server.sshbind);
  ssh_finalize();
}
