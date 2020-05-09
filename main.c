#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <libssh/callbacks.h>
#include <libssh/server.h>

#include "server.h"
#include "utils.h"

static int copy_fd_to_chan(socket_t fd, int revents, void *userdata) {
  ssh_channel chan = (ssh_channel)userdata;
  char buf[2048];
  int sz = 0;

  if (!chan) {
    close(fd);
    return -1;
  }
  if (revents & POLLIN) {
    sz = read(fd, buf, 2048);
    if (sz > 0) {
      write(1, buf, sz);
      fflush(stdout);
      ssh_channel_write(chan, buf, sz);
    }
  }
  if (revents & POLLHUP) {
    ssh_channel_close(chan);
    sz = -1;
  }
  return sz;
}

static int copy_chan_to_fd(ssh_session session, ssh_channel channel, void *data,
                           uint32_t len, int is_stderr, void *userdata) {
  int fd = *(int *)userdata;
  int sz;
  (void)session;
  (void)channel;
  (void)is_stderr;

  sz = write(fd, data, len);
  write(1, data, len);
  fflush(stdout);
  return sz;
}

static void chan_close(ssh_session session, ssh_channel channel,
                       void *userdata) {
  int fd = *(int *)userdata;
  (void)session;
  (void)channel;

  close(fd);
}

static int chan_pty(ssh_session session, ssh_channel channel, const char *term,
                    int cols, int rows, int py, int px, void *userdata) {
  return SSH_OK;
}

static int chan_shell(ssh_session session, ssh_channel channel,
                      void *userdata) {
  return SSH_OK;
}

struct ssh_channel_callbacks_struct cb = {
    .channel_data_function = copy_chan_to_fd,
    .channel_eof_function = chan_close,
    .channel_close_function = chan_close,
    .channel_pty_request_function = chan_pty,
    .channel_shell_request_function = chan_shell,
};

int mainloop(ssh_event event, ssh_channel chan, int sock) {
  int result = -1;
  short events = POLLIN | POLLPRI | POLLERR | POLLHUP | POLLNVAL;

  cb.userdata = &sock;
  ssh_callbacks_init(&cb);
  ssh_set_channel_callbacks(chan, &cb);

  if (event == NULL) {
    printf("Couldn't get an event\n");
    goto out;
  }
  if (ssh_event_add_fd(event, sock, events, copy_fd_to_chan, chan) != SSH_OK) {
    printf("Couldn't add an fd to the event: %s\n", ssh_get_error(chan));
    goto out;
  }

  do {
    ssh_event_dopoll(event, 1000);
  } while (!ssh_channel_is_closed(chan));

  ssh_event_remove_fd(event, sock);

  result = 0;
out:
  if (event)
    ssh_event_free(event);
  return result;
}

struct session_data {
  ssh_channel channel;
  int authenticated;
  const char *username;
  ssh_key key;
  int sock;
};

static int auth_pubkey(ssh_session session, const char *user, ssh_key pubkey,
                       char signature_state, void *userdata) {
  struct session_data *sdata = (struct session_data *)userdata;
  (void)session;
  if (sdata->channel)
    return SSH_ERROR;
  if (signature_state != SSH_PUBLICKEY_STATE_NONE &&
      signature_state != SSH_PUBLICKEY_STATE_VALID) {
    _ssh_log(SSH_LOG_INFO, "auth_pubkey", "Invalid signature state");
    return SSH_AUTH_DENIED;
  }
  if (strcmp(user, sdata->username) == 0 &&
      ssh_key_cmp(pubkey, sdata->key, 0) == 0) {
    sdata->authenticated = 1;
    return SSH_AUTH_SUCCESS;
  }
  return SSH_AUTH_DENIED;
}

static ssh_channel channel_open(ssh_session session, void *userdata) {
  struct session_data *sdata = (struct session_data *)userdata;
  if (sdata->channel != NULL) {
    ssh_channel_close(sdata->channel);
  }
  if (sdata->sock != -1) {
    close(sdata->sock);
    sdata->sock = -1;
  }
  sdata->channel = ssh_channel_new(session);
  return sdata->channel;
}

int child(ssh_session session, const char *username, ssh_key key,
          struct addrinfo *addr) {
  int result = -1;
  printf("child started\n");

  struct session_data sdata = {
      .username = username,
      .key = key,
      .sock = -1,
  };

  struct ssh_server_callbacks_struct server_cb = {
      .userdata = &sdata,
      .auth_pubkey_function = auth_pubkey,
      .channel_open_request_session_function = channel_open,
  };
  ssh_callbacks_init(&server_cb);
  ssh_set_server_callbacks(session, &server_cb);

  if (ssh_handle_key_exchange(session) == SSH_ERROR) {
    _ssh_log(SSH_LOG_INFO, "child", "Client key exchange error: %s\n",
             ssh_get_error(session));
    goto out;
  }

  ssh_event event = ssh_event_new();
  ssh_set_auth_methods(session, SSH_AUTH_METHOD_PUBLICKEY);
  ssh_event_add_session(event, session);

  while (!sdata.authenticated || sdata.channel == NULL)
    if (ssh_event_dopoll(event, 1000) == SSH_ERROR)
      goto out;

  sdata.sock = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
  if (sdata.sock == -1) {
    perror("socket");
    goto out;
  }
  if (connect(sdata.sock, addr->ai_addr, addr->ai_addrlen) == -1) {
    perror("connect");
    goto out;
  }

  result = mainloop(event, sdata.channel, sdata.sock);
out:
  ssh_event_remove_session(event, session);
  return result;
}

int main(int argc, char *argv[]) {
  struct forward_server_data fs_data = {0};
  if (parse_args(argc, argv, &fs_data) == -1)
    exit(EXIT_FAILURE);

  ssh_set_log_level(SSH_LOG_TRACE);

  int res;
  ssh_bind sshbind = ssh_bind_new();
  if (sshbind == NULL) {
    perror("ssh bind new");
    exit(EXIT_FAILURE);
  }
  res = ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, "server.key");
  if (res < 0) {
    printf("ssh bind set rsakey error: %s\n", ssh_get_error(sshbind));
    goto out;
  }

  res = ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &fs_data.port);
  if (res < 0) {
    printf("ssh bind set port error: %s\n", ssh_get_error(sshbind));
    goto out;
  }

  res = ssh_bind_listen(sshbind);
  if (res < 0) {
    printf("ssh bind listen error: %s\n", ssh_get_error(sshbind));
    goto out;
  }

  printf("Started sshforward server on port %u\n", fs_data.port);

  ssh_session session = ssh_new();
  while (1) {
    res = ssh_bind_accept(sshbind, session);
    if (res == SSH_ERROR) {
      printf("Failed to accept connection: %s\n", ssh_get_error(sshbind));
      goto out;
    }
    switch (fork()) {
    case -1:
      perror("fork");
      goto out;
    case 0:
      exit(child(session, fs_data.username, fs_data.key, &fs_data.target));
    default:
      break;
    }
  }

out:
  ssh_bind_free(sshbind);
  ssh_finalize();
}
