all: c go

go: clean service.fbs
	./bin/flatc --go service.fbs
	mv service ../proxy-service/internal/

c: clean service.fbs
	mkdir -p c/
	./bin/flatcc -a service.fbs -o c/
	./bin/flatcc-doc.sh service.fbs service c/

.PHONY: clean
clean:
	rm -rf c/
	rm -rf ../proxy-service/internal/service/

