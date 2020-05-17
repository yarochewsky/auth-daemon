all: bin daemon server

INCLUDE=-I../protocol/c -I../protocol/include -I./
LINK=-L../protocol/lib -L../server/external-libs/
GCC=gcc -Wall -g

bin:
	mkdir -p bin/

daemon: commslib/commslib.o protolib/protolib.o server/handlers/handlers.o \
				server/access/access.o server/server.o daemon.o
	$(GCC) $(INCLUDE) $(LINK) daemon.o server/server.o server/access/access.o commslib/commslib.o \
		protolib/protolib.o server/handlers/handlers.o -o ./bin/daemon -lflatccrt -levent

daemon.o: daemon.c
	$(GCC) $(INCLUDE) -I./commslib -I./server -c $< -o $@

server/server.o: server/server.c server/access/access.h server/server.h
	$(GCC) $(INCLUDE) -I./include -c $< -o $@

commslib/commslib.o: commslib/commslib.c commslib/commslib.h protolib/protolib.h
	$(GCC) $(INCLUDE) -c $< -o $@

server/access/access.o: server/access/access.c server/access/access.h commslib/commslib.h protolib/protolib.h
	$(GCC) $(INCLUDE) -c $< -o $@

server/handlers/handlers.o: server/handlers/handlers.c server/handlers/handlers.h server/access/access.h
	$(GCC) $(INCLUDE) -c $< -o $@

protolib/protolib.o: protolib/protolib.c protolib/protolib.h
	$(GCC) $(INCLUDE) -c $< -o $@

.PHONY: clean
clean:
	rm -rf ./bin/
	find . -type f -name '*.o' -delete
