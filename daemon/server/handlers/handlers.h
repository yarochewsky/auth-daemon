#ifndef HANDLERS_H
#define HANDLERS_H

#include "service_reader.h"
#include "server/access/access.h"

#undef ns
#define ns(x) FLATBUFFERS_WRAP_NAMESPACE(service, x) // Specified in the schema.

size_t handle_heartbeat_request(ns(HeartbeatRequest_table_t) hb_req, uint64_t seq_num, uint8_t** ret_buf);
size_t handle_authorize_process_request(struct access_store* access, ns(AuthorizeProcessRequest_table_t) req, uint64_t seq_num, uint8_t** ret_buf);

#endif // HANDLERS_H
