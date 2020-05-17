#include <stdio.h>

#include "service_reader.h"
#include "service_builder.h"
#include "service_verifier.h"

#include "protolib.h"

/**
 * new_builder allocates and creates a new flatcc builder
 *
 * @returns a pointer to builder ready to start building messages.
 * Client is responsible for calling free_builder(B) after use.
 *
**/
static flatcc_builder_t* new_builder();

/**
 * free_builder: release resources allocated for builder
 *
 * @B: builder to free
 *
**/
static void free_builder(flatcc_builder_t* B);


size_t marshall_heartbeat_request(uint64_t seq_num, uint8_t** ret_buf) {
  uint8_t *buf;
  size_t size; 

  flatcc_builder_t* B = new_builder();
  if (!B) {
    return 0;
  }

  ns(HeartbeatRequest_start(B));
  ns(HeartbeatRequest_ref_t) req = ns(HeartbeatRequest_end(B));  

  ns(Message_start_as_root(B));
  ns(Message_seq_num_add(B, seq_num));
  ns(Payload_union_ref_t) payload = ns(Payload_as_HeartbeatRequest(req));

  ns(Message_payload_add(B, payload));
  ns(Message_end_as_root(B));

  buf = flatcc_builder_finalize_buffer(B, &size); 
  
  free_builder(B);

  *ret_buf = buf;
  return size;
}

size_t marshall_heartbeat_response(uint64_t seq_num, uint8_t** ret_buf) {
  uint8_t* buf;
  size_t size;

  flatcc_builder_t* B = new_builder();
  if (!B) {
    return 0;
  }

  ns(HeartbeatResponse_start(B));
  ns(HeartbeatResponse_ref_t) resp = ns(HeartbeatResponse_end(B));  

  ns(Message_start_as_root(B));
  ns(Message_seq_num_add(B, seq_num));

  ns(Payload_union_ref_t) payload = ns(Payload_as_HeartbeatResponse(resp));

  ns(Message_payload_add(B, payload));
  ns(Message_end_as_root(B));

  buf = flatcc_builder_finalize_buffer(B, &size); 

  free_builder(B);

  *ret_buf = buf;
  return size;
}

size_t marshall_authorize_process_request(struct authorize_process_request* ap_req, uint64_t seq_num, uint8_t** ret_buf) {
  uint8_t* buf;
  size_t size;

  if (!ap_req) {
    perror("invalid authorize process request");
    return 0;
  }

  flatcc_builder_t* B = new_builder();
  if (!B) {
    return 0;
  }

  ns(AuthorizeProcessRequest_start(B));
  ns(AuthorizeProcessRequest_old_pid_add(B, ap_req->old_pid));
  ns(AuthorizeProcessRequest_new_pid_add(B, ap_req->new_pid));
  ns(AuthorizeProcessRequest_ref_t) resp = ns(AuthorizeProcessRequest_end(B));

  ns(Message_start_as_root(B));
  ns(Message_seq_num_add(B, seq_num));

  ns(Payload_union_ref_t) payload = ns(Payload_as_AuthorizeProcessRequest(resp));

  ns(Message_payload_add(B, payload));
  ns(Message_end_as_root(B));

  buf = flatcc_builder_finalize_buffer(B, &size); 

  free_builder(B);

  *ret_buf = buf;
  return size;
}

struct authorize_process_request* unmarshall_authorize_process_request(ns(AuthorizeProcessRequest_table_t)* req) {
  struct authorize_process_request* ap_req = malloc(sizeof(struct authorize_process_request));
  if (!ap_req) {
    perror("no memory authorize process request");
    return NULL;
  }
  memset(ap_req, 0, sizeof(struct authorize_process_request));
  
  ap_req->old_pid = ns(AuthorizeProcessRequest_old_pid_get(*req));
  ap_req->new_pid = ns(AuthorizeProcessRequest_new_pid_get(*req));

  return ap_req;
}

size_t marshall_authorize_process_response(struct authorize_process_response* ap_resp, uint64_t seq_num, uint8_t** ret_buf) {
  uint8_t* buf;
  size_t size;

  if (!ap_resp) {
    perror("invalid authorize process request");
    return 0;
  }

  flatcc_builder_t* B = new_builder();
  if (!B) {
    return 0;
  }

  ns(AuthorizeProcessResponse_start(B));
  ns(AuthorizeProcessResponse_ref_t) resp = ns(AuthorizeProcessResponse_end(B));

  ns(Message_start_as_root(B));
  ns(Message_seq_num_add(B, seq_num));

  ns(Payload_union_ref_t) payload = ns(Payload_as_AuthorizeProcessResponse(resp));

  ns(Message_payload_add(B, payload));
  ns(Message_end_as_root(B));

  buf = flatcc_builder_finalize_buffer(B, &size); 

  free_builder(B);

  *ret_buf = buf;
  return size;
}

static void free_builder(flatcc_builder_t* B) {
  flatcc_builder_clear(B);
  free(B);
}

static flatcc_builder_t* new_builder() {
  flatcc_builder_t* B = malloc(sizeof(flatcc_builder_t));
  if (!B) {
    perror("no memory for builder");
    return NULL;
  } 
  memset(B, 0, sizeof(flatcc_builder_t));
  flatcc_builder_init(B);
  return B;
}
