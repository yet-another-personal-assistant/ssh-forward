#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "server.h"
#include "utils.h"

int make_addr(const char *host, const char *service, struct addrinfo *result) {
  struct addrinfo hints, *ai, *rp;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(host, service, &hints, &ai) != 0) {
    perror("getaddrinfo");
    return -1;
  }

  bzero(result, sizeof(struct addrinfo));

  for (rp = ai; rp != NULL; rp = rp->ai_next) {
    int sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sock == -1)
      continue;
    int result = connect(sock, rp->ai_addr, rp->ai_addrlen);
    close(sock);
    if (result != -1)
      break;
  }

  if (rp == NULL) {
    printf("Could not connect\n");
    return -1;
  }

  result->ai_family = rp->ai_family;
  result->ai_socktype = rp->ai_socktype;
  result->ai_protocol = rp->ai_protocol;
  result->ai_addrlen = rp->ai_addrlen;
  result->ai_addr = malloc(rp->ai_addrlen);
  if (result->ai_addr == NULL) {
    perror("malloc addr");
    return -1;
  }
  memcpy(result->ai_addr, rp->ai_addr, rp->ai_addrlen);

  freeaddrinfo(ai);
  return 0;
}

static void usage(const char *appname) {
  printf("Usage: %s <user> <key> <host> <port> [<local port>]\n", appname);
  printf("  user - username to accept\n");
  printf("  key - public key to authenticate\n");
  printf("  host, port - where to forward to\n");
  printf("  local port - where to listen (default 3000)\n");
}

int parse_args(int argc, char *argv[], struct forward_server_data *fs_data) {
  switch (argc) {
  case 5:
    fs_data->port = 3000;
    break;
  case 6:
    if (sscanf(argv[5], "%d", &fs_data->port) != 1) {
      printf("port is not a number: %s\n", argv[5]);
      return -1;
    }
    break;
  default:
    usage(argv[0]);
    return -1;
  }
  if (make_addr(argv[3], argv[4], &fs_data->target) == -1)
    return -1;
  fs_data->username = strdup(argv[1]);
  if (fs_data->username == NULL) {
    perror("strdup");
    return -1;
  }
  fs_data->key = ssh_key_new();
  if (fs_data->key == NULL ||
      ssh_pki_import_pubkey_file(argv[2], &fs_data->key) == SSH_ERROR) {
    perror("ssh key load");
    return -1;
  }
  return 0;
}

