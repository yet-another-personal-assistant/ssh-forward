#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>

#include <libssh/server.h>

#include "server.h"
#include "session.h"

static void sig_chld(int signo) {
  int statol;
  if (waitpid(-1, &statol, WUNTRACED) < 0) {
    perror("waitpid error");
    exit(errno);
  }
  _ssh_log(SSH_LOG_DEBUG, "sig_chld", "Child worker exited");
}

static void mainloop(struct forward_server *server) {
  ssh_session session = ssh_new();
  while (1) {
    if (ssh_bind_accept(server->sshbind, session) == SSH_ERROR) {
      printf("Failed to accept connection: %s\n",
             ssh_get_error(server->sshbind));
      return;
    }
    switch (fork()) {
    case -1:
      perror("fork");
      return;
    case 0:
      exit(handle_session(session, &server->data));
    default:
      break;
    }
  }
}

static void set_sigchld_handler() {
  struct sigaction act;
  sigemptyset(&act.sa_mask);

  act.sa_handler = sig_chld;
  act.sa_flags |= SA_RESTART;
  if (sigaction(SIGCHLD, &act, NULL) == -1) {
    perror("sigaction(CHLD)");
    exit(EXIT_FAILURE);
  }
}

int main(int argc, char *argv[]) {
  ssh_set_log_level(SSH_LOG_TRACE);
  set_sigchld_handler();

  struct forward_server server = {0};
  if (setup_server(argc, argv, &server) == -1)
    goto out;

  _ssh_log(SSH_LOG_TRACE, "main", "Server is set up");

  if (ssh_bind_listen(server.sshbind) == SSH_OK) {
    _ssh_log(SSH_LOG_TRACE, "main", "Server is listening");
    mainloop(&server);
  } else
    printf("ssh bind listen error: %s\n", ssh_get_error(server.sshbind));

out:
  if (server.sshbind != NULL)
    ssh_bind_free(server.sshbind);
  ssh_finalize();
}
