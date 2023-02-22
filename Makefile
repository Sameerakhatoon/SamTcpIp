CC       = gcc
CFLAGS   = -g -Wall -Wno-unused-function -I.
OBJECTS  = build/graph.o \
           build/net.o \
           build/topologies.o \
           build/gluethread/glthread.o

all: testapp

testapp: build/testapp.o $(OBJECTS)
	$(CC) $(CFLAGS) build/testapp.o $(OBJECTS) -o testapp

build/testapp.o: testapp.c graph.h net.h
	@mkdir -p build
	$(CC) $(CFLAGS) -c testapp.c -o build/testapp.o

build/graph.o: graph.c graph.h net.h
	@mkdir -p build
	$(CC) $(CFLAGS) -c graph.c -o build/graph.o

build/net.o: net.c net.h graph.h
	@mkdir -p build
	$(CC) $(CFLAGS) -c net.c -o build/net.o

build/topologies.o: topologies.c graph.h net.h
	@mkdir -p build
	$(CC) $(CFLAGS) -c topologies.c -o build/topologies.o

build/gluethread/glthread.o: gluethread/glthread.c gluethread/glthread.h
	@mkdir -p build/gluethread
	$(CC) $(CFLAGS) -c gluethread/glthread.c -o build/gluethread/glthread.o

clean:
	rm -f testapp
	rm -rf build

.PHONY: all clean
