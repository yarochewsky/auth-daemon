#ifndef SERVER_H
#define SERVER_H

/**
 * new_server: creates a new server bound to addr
 *
 * @addr: address path of socket to bind server to
 *
 * @returns server instance. The caller is responsible
 * for memory cleanup
 *
**/
struct server_state* new_server(char* addr);

/**
 * start_server: starts server listening to clients.
 *
 * This call blocks until server errors or is stopped.
 *
 * @returns -1 if server exited with error or 0 if exited cleanly
 *
**/
int start_server(struct server_state*);
void stop_server(struct server_state*);


#endif // SERVER_H
