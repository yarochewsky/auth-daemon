#include <stdio.h>

#include "protolib/protolib.h"

#include "handlers.h"

size_t handle_heartbeat_request(ns(HeartbeatRequest_table_t) hb_req, uint64_t seq_num, uint8_t** ret_buf) {
  size_t buf_size;

  buf_size = marshall_heartbeat_response(seq_num, ret_buf);

  return buf_size;
}

size_t handle_authorize_process_request(struct access_store* access, ns(AuthorizeProcessRequest_table_t) req, uint64_t seq_num, uint8_t** ret_buf) {
  struct authorize_process_request* ap_req;
  struct authorize_process_response ap_resp;
  int auth_err;

  ap_req = unmarshall_authorize_process_request(&req);
  if (!ap_req) {
    fprintf(stderr, "invalid authorize process request\n");
    return 0;
  }

  if (ap_req->old_pid == 0) {
    // we authorize the new process
    auth_err = authorize_new_process(access, ap_req->new_pid);
  } else {
    // we swap the old process with the new
    auth_err = swap_processes(access, ap_req->old_pid, ap_req->new_pid);
  }

  if (auth_err < 0) {
    fprintf(stderr, "failed to reauth new process\n");
    free(ap_req);
    return 0;
  }

  return marshall_authorize_process_response(&ap_resp, seq_num, ret_buf);
}
