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

#include "service_reader.h"
#include "service_builder.h"
#include "service_verifier.h"
#include "protolib/protolib.h"
#include "commslib.h"

#define READ_TIMEOUT 10 // timeout for socket read in microseconds

#undef ns
#define ns(x) FLATBUFFERS_WRAP_NAMESPACE(service, x) // Specified in the schema.


/**
 * format_msg: formats a buf into a msghdr struct with permission control
 *
 * @payload: message payload
 * @payload_len: size of payload in bytes
 * @hdr: return parameter of resulting msghdr
 *
 * @returns -1 on error or 0 on success
 *
 * Callers responsible for hdr's memory resources
*/
static int format_msg(uint8_t* buf, int buf_len, struct msghdr** hdr);

/**
 * set_non_blocking: sets the fd to non blocking
 *
 * @fd: socket fd
 *
 * @returns 0 on success, -1 otherwise
 *
**/
static int set_non_blocking(int fd);


/**
 * clear_non_blocking: clears non blocking flag from fd
 *
 * @fd: socket fd
 *
 * @returns 0 on success, -1 otherwise
 *
**/
static int clear_non_blocking(int fd);

int resolve_address(char* addr_path, struct sockaddr_un* addr) {
  if (!addr) {
    fprintf(stderr, "input addr is null\n");
    return -1;
  }
  memset(addr, 0, sizeof(struct sockaddr_un));

  if (strlen(addr_path) > sizeof(addr->sun_path)) {
    fprintf(stderr, "socket path too long\n");
    return -1;
  }
 
  addr->sun_family = AF_UNIX;
  strncpy(addr->sun_path, addr_path, sizeof(addr->sun_path) - 1);

  return 0;
}

int setup_datagram_socket(char* addr) {
  struct sockaddr_un client;
  int fd, enabled;

  if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
    perror("failed to create socket");
    return -1;
  }

  if (strlen(addr) > sizeof(client.sun_path)) {
    fprintf(stderr, "socket path too long\n");
    return -1;
  }

  memset(&client, 0, sizeof(struct sockaddr_un));
  client.sun_family = AF_UNIX;
  strncpy(client.sun_path, addr, sizeof(client.sun_path) - 1);
  unlink(client.sun_path);

  if (bind(fd, (struct sockaddr*) &client, sizeof(struct sockaddr_un)) < 0) {
    perror("failed to bind");
    return -1;
  }

  enabled = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled)) < 0) {
    perror("failed to set up authenticated socket");
    return -1;
  } 

  struct timeval read_timeout = {
    .tv_sec = 0,
    .tv_usec = READ_TIMEOUT,
  };  
  if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &read_timeout, sizeof(read_timeout)) < 0) {
    perror("failed to set timeout for socket");
    return -1;
  }
 
  return fd;
}

int receive_msg(int dst_fd, struct msghdr** msg) {
  struct msghdr* hdr; 
  int bytes_read;
  struct iovec iov[1];
  uint8_t buf[1024];
  struct sockaddr_un client;
  struct cmsghdr* cmh;
  struct ucred* ucred_data;

  hdr = malloc(sizeof(struct msghdr));
  if (!hdr) {
    perror("no memory available for message");
    return -1;
  }
  memset(hdr, 0, sizeof(struct msghdr));

  memset(iov, 0, sizeof(iov));
  iov[0].iov_base = buf;
  iov[0].iov_len = sizeof(buf);

  hdr->msg_iov = iov;
  hdr->msg_iovlen = 1;

  memset(&client, 0, sizeof(struct sockaddr_un));
  hdr->msg_name = &client;
  hdr->msg_namelen = sizeof(struct sockaddr_un);

  union {
    struct cmsghdr cmh;
    char control[CMSG_SPACE(sizeof(struct ucred))];
  } control_un;
  memset(&control_un, 0, sizeof(control_un));

  control_un.cmh.cmsg_len = CMSG_LEN(sizeof(struct ucred));
  control_un.cmh.cmsg_level = SOL_SOCKET;
  control_un.cmh.cmsg_type = SCM_CREDENTIALS;

  hdr->msg_control = control_un.control;
  hdr->msg_controllen = sizeof(control_un.control);

  bytes_read = recvmsg(dst_fd, hdr, 0 | O_NONBLOCK);
  if (bytes_read < 0) {
    perror("failed to receive message");
    free(hdr);
    return -1;
  }

  if (bytes_read == 0) {
    fprintf(stderr, "process did not send anything\n");
    free(hdr);
    return -1;
  }

  *msg = hdr;
  return bytes_read;
}

int send_msg(int src_fd, uint8_t* payload, size_t payload_len) {
  int fd, enabled, return_code;
  struct sockaddr_un source;
  struct msghdr* msg;

  if (format_msg(payload, payload_len, &msg) < 0) {
    perror("failed to format payload");
    return -1;
  }
  return_code = sendmsg(src_fd, msg, 0);
  free(msg);

  return return_code;
}

int connect_to_destination(int src_fd, struct sockaddr_un* dst) {
  if (connect(src_fd, (struct sockaddr*) dst, sizeof(struct sockaddr_un)) < 0) {
    perror("could not connect to destination");
    return -1;
  } 
  return 0;
}

int format_msg(uint8_t* payload, int payload_len, struct msghdr** hdr_ret) {
  struct iovec iov[1];
  struct msghdr* hdr;

  hdr = malloc(sizeof(struct msghdr));
  if (!hdr) {
    return -1;
  }
  memset(hdr, 0, sizeof(struct msghdr));

  memset(iov, 0, sizeof(iov));
  iov[0].iov_base = payload;
  iov[0].iov_len = payload_len;
  hdr->msg_iov = iov;
  hdr->msg_iovlen = 1;

  hdr->msg_control = NULL;
  hdr->msg_controllen = 0;
  
  *hdr_ret = hdr;
  return 0;
}

struct ucred* get_header_credentials(struct msghdr* hdr) {
  struct cmsghdr* cmh;

  cmh = CMSG_FIRSTHDR(hdr);

  if (cmh && cmh->cmsg_len == CMSG_LEN(sizeof(struct ucred)) &&
      cmh->cmsg_level == SOL_SOCKET && cmh->cmsg_type == SCM_CREDENTIALS)
  {
    return (struct ucred*) CMSG_DATA(cmh);
  }
  return NULL;
}

static int set_non_blocking(int fd) {
  int flags;

  if ((flags = fcntl(fd, F_GETFL, 0)) < 0) {
    return -1;
  }
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int clear_non_blocking(int fd) {
  int flags;

  if ((flags = fcntl(fd, F_GETFL, 0)) < 0) {
    return -1;
  }
  flags &= ~O_NONBLOCK;
  return fcntl(fd, F_SETFL, flags);
}
