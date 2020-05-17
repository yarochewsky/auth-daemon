#ifndef __ACCESS_H_
#define __ACCESS_H_

#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>

#include "service_reader.h"

#undef ns
#define ns(x) FLATBUFFERS_WRAP_NAMESPACE(service, x) // Specified in the schema.

// The access store defines what processes can talk to the server via its
// IPC socket. Incoming messages must have ancilliary data which informs
// the requestor's pid, which can then be authrorized against the store.

struct access_store;

/**
 * new_access_store: instantiate a new access store with a capacity
 *
 * @capacity: maximum number of whitelistable pids to hold
 *
 * @returns a new instance of access store. Caller must free after use by calling
 * free_access_store.
**/
struct access_store* new_access_store(size_t capcity);

/**
 * free_access_store: free resources used by access store.
 *
 * @store: instance of access store to free
*/
void free_access_store(struct access_store* store);

/**
 * check_authentication: checks if a candidate process is whitelisted by the store
 * candidate: pid of iniquiring process
 *
 * @store: access store to check auth
 * @candidate: process id to check auth
 *
 * @returns 1 on authorized and 0 otherwise
*/
uint8_t check_authentication(struct access_store* store, pid_t candidate);

/**
 * swap_processes: revokes access and authorization of old_process, and insert new_process
 * with all of old_process' roles and auth.
 *
 * @store: access store
 * @old_process: pid of process to revoke
 * @new_process: pid of process to inherit access
 *
 * @returns 0 on success or -1 if old_process does not exist
*/
int swap_processes(struct access_store* store, pid_t old_process, pid_t new_process);

/**
 * authorize_new_process: authorizes a new pid
 *
 * @store: access store
 * @process: pid of process to authorize handlers on
 *
 * @returns -1 on error or 0 on success
*/
int authorize_new_process(struct access_store* store, pid_t process);

#endif
