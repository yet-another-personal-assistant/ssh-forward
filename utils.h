#ifndef _UTILS_H_
#define _UTILS_H_

#include <netdb.h>

#include "server.h"

int make_addr(const char *host, const char *service, struct addrinfo *result);
int parse_args(int argc, char *argv[], struct forward_server_data *fs_data);

#endif  // _UTILS_H_
