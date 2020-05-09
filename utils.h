#ifndef _UTILS_H_
#define _UTILS_H_

#include <netdb.h>

#include "server.h"

int parse_args(int argc, char *argv[], struct forward_server_data *fs_data, unsigned int *port);

#endif  // _UTILS_H_
