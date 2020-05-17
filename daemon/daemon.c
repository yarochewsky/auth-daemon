#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/un.h>

#include "commslib/commslib.h"
#include "protolib/protolib.h"
#include "service_reader.h"
#include "service_builder.h"
#include "service_verifier.h"
#include "server.h"

#undef ns
#define ns(x) FLATBUFFERS_WRAP_NAMESPACE(service, x) // Specified in the schema.

#define PROCESS_MONITOR_ADDR "/tmp/process_monitor"
#define PROXY_ADDR "/tmp/proxy"
#define SERVER_ADDR "/tmp/server"
#define PROXY_BIN "/root/dead-unit/proxy-service/bin/proxy"

#define SLEEP_TIMEOUT 2
#define MAX_LAG 2

#define OTHER_PROCESS(i) (!i)

struct process {
  char addr[255];

  int lag;
  int max_lag;
  uint64_t seq_num;

  pid_t pid;
};

static void spawn_server();
static void spawn_proxy();

void monitor_processes(int fd, struct process** processes);
static int recover_process(int fd, struct process** processes, size_t process_entry);
static int handle_heartbeat(int fd, struct process* p);
int authorize_peer(int fd, struct process* peer, pid_t old_pid, pid_t new_pid);

int main(int argc, char** argv) {
  pid_t server_pid, proxy_pid;
  int status;
  int fd;

  fd = setup_datagram_socket(PROCESS_MONITOR_ADDR);
  if (fd < 0) {
    perror("failed to create socket");
    return -1;
  }

  proxy_pid = fork();
  if (proxy_pid < 0) {
    perror("child fork failed");
    return -1;
  }

  if (proxy_pid == 0) {
    spawn_proxy();
  } else {
    server_pid = fork();
    if (server_pid < 0) {
      perror("server fork failed");
      return -1;
    }
  
    if (server_pid == 0) {
      spawn_server();
    } else {
      printf("Starting server at %d and proxy at %d\n", server_pid, proxy_pid);

      struct process server_process = {
        .addr = SERVER_ADDR,
        .lag = 0,
        .max_lag = MAX_LAG,
        .seq_num = 0,
        .pid = server_pid,
      };

      struct process proxy_process = {
        .addr = PROXY_ADDR,
        .lag = 0,
        .max_lag = MAX_LAG,
        .seq_num = 0,
        .pid = proxy_pid,
      };

      struct process* processes[2] = { &server_process, &proxy_process };

      // we need to wait for proxy to come alive
      sleep(3);

      authorize_peer(fd, &server_process, 0, proxy_pid);
      authorize_peer(fd, &proxy_process, 0, server_pid);

      monitor_processes(fd, processes);
    }
  }
}

void monitor_processes(int fd, struct process** processes) {
  uint8_t* payload;
  struct sockaddr_un server;
  size_t payload_len;
  pid_t old_pid;

  while (1) {
    for (size_t i = 0; i < 2; i++) {
      struct process* p = processes[i];

      payload_len = marshall_heartbeat_request(p->seq_num, &payload);
      if (payload_len == 0) {
        perror("failed to render payload");
        // our fault, treat as success
        p->lag = 0;
        goto NEXT;
      }

      if (resolve_address(p->addr, &server) < 0) {
        perror("could not resolve destination address");
        p->lag = 0;
        goto NEXT;
      }

      if (connect_to_destination(fd, &server) < 0) {
        perror("could not connect to destination");
        p->lag++;
        if (p->lag >= p->max_lag) {
          recover_process(fd, processes, i);
        }
        goto NEXT;
      }
      
      if (send_msg(fd, payload, payload_len) < 0) {
        perror("message failed");
        p->lag++;
        if (p->lag >= p->max_lag) {
          recover_process(fd, processes, i);
        }
        goto NEXT;
      }

      if (handle_heartbeat(fd, p) < 0) {
        p->lag++;
        if (p->lag >= p->max_lag) {
          recover_process(fd, processes, i);
        }
        goto NEXT;
      }

      NEXT: {
        p->seq_num++;
        free(payload);
        sleep(SLEEP_TIMEOUT);
      }
    }
  }
}

static int recover_process(int fd, struct process** processes, size_t process_entry) {
  int status;
  struct process* p, *peer;
  pid_t new_pid, old_pid;

  p = processes[process_entry];
  old_pid = p->pid;
  
  printf("Killing %d\n", old_pid);
  kill(old_pid, SIGKILL);

  printf("Reaping %d\n", old_pid);
  waitpid(old_pid, &status, 0);

  new_pid = fork();
  if (new_pid < 0) {
    perror("failed to fork new process");
    return -1;
  }
  
  if (new_pid == 0) {
    if (strcmp(p->addr, SERVER_ADDR) == 0) {
      spawn_server();
    } else {
      spawn_proxy();
    }
  } else {
    p->seq_num = 0;
    p->lag = 0;
    p->pid = new_pid;
    peer = processes[OTHER_PROCESS(process_entry)];
    return authorize_peer(fd, peer, old_pid, p->pid);
  }

  return -1;
}

static int handle_heartbeat(int fd, struct process* p) {
  struct msghdr* hdr; 
  struct ucred* ucred_data;

  if (receive_msg(fd, &hdr) < 0) {
    perror("pm: error receiving heartbeat");
    return -1;
  } 

  ucred_data = get_header_credentials(hdr);
  if (!ucred_data || ucred_data->pid != p->pid) {
    fprintf(stderr, "pm: empty or invalid credentials\n");
    free(hdr);
    return -1;
  }

  return 0;
}

int authorize_peer(int fd, struct process* peer, pid_t old_pid, pid_t new_pid) {
  uint8_t* payload;
  struct sockaddr_un server;
  size_t payload_len;
  struct msghdr* hdr; 
  struct ucred* ucred_data;

  struct authorize_process_request r = {
    .old_pid = old_pid,
    .new_pid = new_pid,
  };

  payload_len = marshall_authorize_process_request(&r, peer->seq_num, &payload);
  if (payload_len == 0) {
    perror("failed to render payload");
    return -1;
  }
  peer->seq_num++;

  if (resolve_address(peer->addr, &server) < 0) {
    perror("could not resolve destination address");
    return -1;
  }

  if (connect_to_destination(fd, &server) < 0) {
    perror("could not connect to destination");
    return -1;
  }
  
  if (send_msg(fd, payload, payload_len) < 0) {
    perror("message failed");
    return -1;
  }

 if (receive_msg(fd, &hdr) < 0) {
    perror("pm: error receiving heartbeat");
    return -1;
  } 

  ucred_data = get_header_credentials(hdr);

  if (!ucred_data || ucred_data->pid != peer->pid) {
    fprintf(stderr, "empty or invalid credentials\n");
    free(hdr);
    return -1;
  }

  free(hdr);
  return 0;
}

static void spawn_server() {
  struct server_state* s;

  s = new_server(SERVER_ADDR);
  if (!s) {
    perror("failed to create server instance");
    return;
  }

  start_server(s);
}

static void spawn_proxy() {
  char* args[2];
  
  args[0] = PROXY_BIN; // first argument is name of the program, by convention
  // null-terminate list of arguments as per execvp man
  args[1] = NULL;

  execvp(PROXY_BIN, args); 
}
