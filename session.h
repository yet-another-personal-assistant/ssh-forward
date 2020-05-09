#ifndef _SESSION_H_
#define _SESSION_H_

#include <libssh/libssh.h>

#include "server.h"

int handle_session(ssh_session session, struct forward_server_data *fs_data);

#endif // _SESSION_H_
