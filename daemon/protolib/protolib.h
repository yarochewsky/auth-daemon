/**
 *  Protolib implements marshalling and unmarshalling of the
 *  messages defined by our protocol, for convenient usage
 *  by the various C programs.
 *
 */

#ifndef PROTOLIB_H
#define PROTOLIB_H

#include <stdint.h>

#include "service_reader.h"
#include "service_builder.h"
#include "service_verifier.h"

#undef ns
#define ns(x) FLATBUFFERS_WRAP_NAMESPACE(service, x) // Specified in the schema.

struct heartbeat_request {};

/**
 * marshall_heartbeart_request: marshalls a new HeartbeatRequest buffer ready to be
 * trasmitted. 
 *
 * @hb_req: heartbeat request to marshall
 * @ret_buf: return parameter of buffer to be marshalled
 *
 * @returns size of the marshalled buffer. Clients are responsible for buffer's memory
*/
size_t marshall_heartbeat_request(uint64_t seq_num, uint8_t** ret_buf);

/**
 * marshall_heartbeart_response: marshalls a new HeartbeatResponse buffer ready to be
 * trasmitted. 
 *
 * @seq_num: sequence number associated with response
 * @ret_buf: return parameter of buffer to be marshalled
 *
 * @returns size of the marshalled buffer. Clients are responsible for buffer's memory
*/
size_t marshall_heartbeat_response(uint64_t seq_num, uint8_t** ret_buf);

struct authorize_process_request {
  uint32_t old_pid;
  uint32_t new_pid;
};

/**
 * marshall_authorize_process_request: marshalls a new AuthorizeProcessRequest buffer ready to be
 * trasmitted. 
 *
 * @ap_req: authorize_process_request struct to marshall
 * @seq_num: sequence number associated with response
 * @ret_buf: return parameter of buffer to be marshalled
 *
 * @returns size of the marshalled buffer. Clients are responsible for buffer's memory
*/
size_t marshall_authorize_process_request(struct authorize_process_request* ap_req, uint64_t seq_num, uint8_t** ret_buf);

/**
 * unmarshall_authorize_process_request: unmarshalls a AuthorizeProcessRequest into an internal struct for
 * easier consumption.
 * 
 * @req: protocol heartbeat response
 *
 * @returns new authorize_process_request pointer. Clients are responsible for its memory.
*/
struct authorize_process_request* unmarshall_authorize_process_request(ns(AuthorizeProcessRequest_table_t)* req);

struct authorize_process_response {
  uint32_t pid;
};

/**
 * marshall_authorize_process_response: marshalls a new AuthorizeProcessResponse buffer ready to be
 * trasmitted. 
 *
 * @ap_resp: authorize_process_response struct to marshall
 * @seq_num: sequence number associated with response
 * @ret_buf: return parameter of buffer to be marshalled
 *
 * @returns size of the marshalled buffer. Clients are responsible for buffer's memory
*/
size_t marshall_authorize_process_response(struct authorize_process_response* ap_resp, uint64_t seq_num, uint8_t** ret_buf);

/**
 * unmarshall_authorize_process_response: unmarshalls a AuthorizeProcessResponse into an internal struct for
 * easier consumption.
 * 
 * @req: protocol heartbeat response
 *
 * @returns new authorize_process_response pointer. Clients are responsible for its memory.
*/
struct authorize_process_response* unmarshall_authorize_process_response(ns(AuthorizeProcessResponse_table_t)* req);


#endif // PROTOLIB_H
