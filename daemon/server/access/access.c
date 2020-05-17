#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "access.h"


struct access_store {
  pid_t* whitelisted;
  size_t whitelisted_size;

  size_t capacity;
};

struct access_store* new_access_store(size_t capacity) {
  struct access_store* store = malloc(sizeof(struct access_store));
  if (!store) {
    return NULL;
  }
  
  pid_t* whitelisted = malloc(sizeof(pid_t) * capacity);
  if (!whitelisted) {
    return NULL;
  }
  memset(whitelisted, 0, sizeof(pid_t) * capacity);
  
  store->whitelisted = whitelisted;
  store->whitelisted_size = 0;
  store->capacity = capacity;

  return store;
}

void free_access_store(struct access_store* store) {
  free(store->whitelisted);
  free(store);
}

uint8_t check_authentication(struct access_store* store, pid_t candidate) {
  for (size_t i = 0; i < store->whitelisted_size; i++) {
    if (store->whitelisted[i] == candidate) {
      return 1;
    }
  }
  return 0;
}

int authorize_new_process(struct access_store* store, pid_t process) {
  for (size_t i = 0; i < store->whitelisted_size; i++) {
    if (store->whitelisted[i] == process) {
      fprintf(stderr, "process already authorized\n");
      return -1;
    }
  }
  if (store->whitelisted_size + 1 > store->capacity) {
    fprintf(stderr, "access control store has reached capacity\n");
    return -1;
  }
  store->whitelisted[store->whitelisted_size] = process;
  store->whitelisted_size++; 
  printf("authorized %d\n", process);

  return 0;
}

int swap_processes(struct access_store* store, pid_t old_process, pid_t new_process) {
  for (size_t i = 0; i < store->whitelisted_size; i++) {
    if (store->whitelisted[i] == old_process) {
      store->whitelisted[i] = new_process;
      printf("authorized %d in place of %d\n", new_process, old_process);
      return 0;
    }
  } 
  return -1;
}

