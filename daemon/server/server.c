#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/un.h>
#include <event2/event.h>

#include "service_reader.h"
#include "service_builder.h"
#include "service_verifier.h"

#include "access/access.h"
#include "protolib/protolib.h"
#include "commslib/commslib.h"
#include "handlers/handlers.h"

#define MAX_WHITELISTED_CAP 5

#undef ns
#define ns(x) FLATBUFFERS_WRAP_NAMESPACE(service, x) // Specified in the schema.

struct server_state {
  struct sockaddr_un* server_address;
  int fd;

  struct access_store* access_control;

  struct event_base* evloop;
  struct event* connect_event;
};

struct client_metadata {
  struct sockaddr_un* client;

  pid_t client_pid;
  uint32_t uid;
  uint32_t gid;

  uint8_t* buf;
  size_t buf_len; 
};

static struct server_state* server_init();
static void server_free(struct server_state* state);

static void connect_handler(int listen_fd, short evtype, void* arg);
static void process_message(int server_fd, struct server_state* state, struct client_metadata* md);
static struct client_metadata* setup_client_metadata(struct msghdr* hdr, struct ucred* ucred_data);

static size_t invoke_procedure(struct server_state* state, ns(Message_table_t)* msg, uint8_t** rendered_buf);
static ns(Payload_union_type_t) route_message(uint8_t* msg_buf, size_t msg_buf_len, ns(Message_table_t)* valid_msg);

struct server_state* new_server(char* addr) {
  struct server_state* state;
  int fd, enabled;
  struct sockaddr_un server;
  socklen_t len;
  pid_t client_pid;
  struct event_base* evloop;

  state = server_init();
  if (!state) {
    perror("could not instantiate server");
    return NULL;
  }

  fd = setup_datagram_socket(addr);
  if (fd < 0) {
    perror("failed to create socket");
    server_free(state);
    return NULL;
  }
  state->fd = fd;

  evloop = event_base_new();
  if (!evloop) {
    perror("could not initialize event loop");
    server_free(state);
    return NULL;
  }
  state->evloop = evloop;
  
  struct event* connect_event = event_new(evloop, fd, EV_READ | EV_PERSIST, connect_handler, (void*) state);
  if (event_add(connect_event, NULL)) {
    perror("failed to add event");
    server_free(state);
    return NULL;
  }
  state->connect_event = connect_event;

  return state;
}

int start_server(struct server_state* state) {
  printf("Starting server...\n");
  if (event_base_dispatch(state->evloop)) {
    perror("failed to start event loop");
    return -1;
  }
  return 0;
}

void stop_server(struct server_state* state) {
  printf("Server exiting...\n");
  if (event_del(state->connect_event)) {
    perror("failed to delete event");
  }
  event_base_free(state->evloop);

  close(state->fd);

  server_free(state);
}

static void process_message(int server_fd, struct server_state* state, struct client_metadata* md) {
  uint8_t* rendered_buf;
  size_t rendered_buf_len;
  ns(Message_table_t) msg;
  ns(Payload_union_type_t) msg_type;

  if (!check_authentication(state->access_control, md->client_pid)) {
    fprintf(stderr, "acess denied for %d\n", md->client_pid);
    goto EXIT;
  }
  
  msg_type = route_message(md->buf, md->buf_len, &msg);
  if (msg_type < 0) {
    perror("failed to match message");
    goto EXIT;
  }

  rendered_buf_len = invoke_procedure(state, &msg, &rendered_buf);
  if (rendered_buf_len == 0) {
    perror("message handling failed");
    goto EXIT;
  }

  if (connect_to_destination(server_fd, md->client) < 0) {
    perror("could not connect to client");
    goto EXIT;
  }

  if (send_msg(server_fd, rendered_buf, rendered_buf_len) < 0) {
    perror("failed to send response");
  }

  EXIT:
    free(md);
}

static void connect_handler(int fd, short evtype, void* arg) {
  struct msghdr* hdr; 
  struct iovec iov[1];
  struct client_metadata* md;
  struct server_state* state;
  struct ucred* ucred_data;
  int bytes_read;

  state = (struct server_state*) arg;

  bytes_read = receive_msg(fd, &hdr);
  if (bytes_read <= 0) {
    perror("failed to receive message");
  }

  if (!(ucred_data = get_header_credentials(hdr))) {
    fprintf(stderr, "empty or invalid credentials\n");
    free(hdr);
    return;
  }

  md = setup_client_metadata(hdr, ucred_data);
  if (!md) {
    free(hdr);
    return;
  }

  process_message(fd, state, md);
}

static struct client_metadata* setup_client_metadata(struct msghdr* hdr, struct ucred* ucred_data) {
  struct client_metadata* md;

  md = malloc(sizeof(struct client_metadata));
  if (!md) {
    fprintf(stderr, "no memory for client md\n");
    return NULL;
  }
  memset(md, 0, sizeof(struct client_metadata));

  md->gid = ucred_data->gid;
  md->uid = ucred_data->uid;
  md->client_pid = (pid_t) ucred_data->pid;

  md->client = hdr->msg_name;

  md->buf = hdr->msg_iov[0].iov_base;
  md->buf_len = hdr->msg_iov[0].iov_len;

  return md;
}

static struct server_state* server_init() {
  struct server_state* state = malloc(sizeof(struct server_state));
  if (!state) {
    return NULL;
  }
  memset(state, 0, sizeof(struct server_state));

  struct access_store* access_control = new_access_store(MAX_WHITELISTED_CAP);
  if (!access_control) {
    server_free(state);
    return NULL;
  }
  
  if (authorize_new_process(access_control, getppid()) < 0) {
    perror("failed to authorize parent process");
    server_free(state);
    return NULL;
  } 
  state->access_control = access_control;

  return state;
}

static size_t invoke_procedure(struct server_state* state, ns(Message_table_t)* msg, uint8_t** rendered_buf) {
  int seq_num;
  size_t len;

  seq_num = ns(Message_seq_num_get(*msg));
  printf("Handling request %d\n", seq_num);

  switch (ns(Message_payload_type_get(*msg))) {
    case ns(Payload_HeartbeatRequest): {
      ns(HeartbeatRequest_table_t) hb_req = ns(Message_payload_get(*msg));
      len = handle_heartbeat_request(hb_req, seq_num, rendered_buf);
      break;
    }
    case ns(Payload_AuthorizeProcessRequest): {
      ns(AuthorizeProcessRequest_table_t) auth_req = ns(Message_payload_get(*msg));
      len = handle_authorize_process_request(state->access_control, auth_req, seq_num, rendered_buf);
      break;
    }
    default:
      len = 0;
  } 

  return len;
}

static ns(Payload_union_type_t) route_message(uint8_t* msg_buf, size_t msg_buf_len, ns(Message_table_t)* valid_msg) {
  ns(Message_table_t) msg;
  
  if (msg_buf_len < sizeof(ns(Message_table_t))) {
    fprintf(stderr, "message is corrupted or malformed\n");
    return -1;
  }

  if (ns(Message_verify_as_root(msg_buf, msg_buf_len)) != 0) {
    fprintf(stderr, "message could not be verified\n");
    return -1;
  }
  msg = ns(Message_as_root(msg_buf));

  *valid_msg = msg;

  return ns(Message_payload_type_get(msg));
}

static void server_free(struct server_state* state) {
  if (state->access_control) {
    free_access_store(state->access_control);
  }
  free(state);
}
