CC       = gcc
CFLAGS   = -g -Wall -Wno-unused-function -I.
LDLIBS   = -lpthread
OBJECTS  = build/graph.o \
           build/net.o \
           build/cli.o \
           build/nwcli.o \
           build/comm.o \
           build/utils.o \
           build/Layer2/layer2.o \
           build/Layer2/l2switch.o \
           build/Layer3/layer3.o \
           build/Layer3/icmp.o \
           build/Layer4/udp.o \
           build/Layer5/ping.o \
           build/tap.o \
           build/topologies.o \
           build/gluethread/glthread.o

all: testapp

testapp: build/testapp.o $(OBJECTS)
	$(CC) $(CFLAGS) build/testapp.o $(OBJECTS) -o testapp $(LDLIBS)

build/testapp.o: testapp.c graph.h net.h cli.h nwcli.h
	@mkdir -p build
	$(CC) $(CFLAGS) -c testapp.c -o build/testapp.o

build/graph.o: graph.c graph.h net.h
	@mkdir -p build
	$(CC) $(CFLAGS) -c graph.c -o build/graph.o

build/net.o: net.c net.h graph.h utils.h
	@mkdir -p build
	$(CC) $(CFLAGS) -c net.c -o build/net.o

build/cli.o: cli.c cli.h
	@mkdir -p build
	$(CC) $(CFLAGS) -c cli.c -o build/cli.o

build/nwcli.o: nwcli.c nwcli.h cli.h graph.h net.h comm.h Layer2/layer2.h Layer3/layer3.h Layer4/udp.h Layer5/ping.h tap.h
	@mkdir -p build
	$(CC) $(CFLAGS) -c nwcli.c -o build/nwcli.o

build/comm.o: comm.c comm.h graph.h
	@mkdir -p build
	$(CC) $(CFLAGS) -c comm.c -o build/comm.o

build/utils.o: utils.c utils.h net.h
	@mkdir -p build
	$(CC) $(CFLAGS) -c utils.c -o build/utils.o

build/Layer2/layer2.o: Layer2/layer2.c Layer2/layer2.h graph.h net.h utils.h comm.h
	@mkdir -p build/Layer2
	$(CC) $(CFLAGS) -c Layer2/layer2.c -o build/Layer2/layer2.o

build/Layer2/l2switch.o: Layer2/l2switch.c Layer2/layer2.h graph.h net.h utils.h comm.h
	@mkdir -p build/Layer2
	$(CC) $(CFLAGS) -c Layer2/l2switch.c -o build/Layer2/l2switch.o

build/Layer3/layer3.o: Layer3/layer3.c Layer3/layer3.h graph.h net.h utils.h comm.h Layer2/layer2.h
	@mkdir -p build/Layer3
	$(CC) $(CFLAGS) -c Layer3/layer3.c -o build/Layer3/layer3.o

build/Layer3/icmp.o: Layer3/icmp.c Layer3/icmp.h utils.h
	@mkdir -p build/Layer3
	$(CC) $(CFLAGS) -c Layer3/icmp.c -o build/Layer3/icmp.o

build/Layer4/udp.o: Layer4/udp.c Layer4/udp.h Layer3/layer3.h graph.h net.h utils.h gluethread/glthread.h
	@mkdir -p build/Layer4
	$(CC) $(CFLAGS) -c Layer4/udp.c -o build/Layer4/udp.o

build/tap.o: tap.c tap.h
	@mkdir -p build
	$(CC) $(CFLAGS) -c tap.c -o build/tap.o

build/Layer5/ping.o: Layer5/ping.c Layer5/ping.h Layer3/layer3.h Layer3/icmp.h graph.h net.h
	@mkdir -p build/Layer5
	$(CC) $(CFLAGS) -c Layer5/ping.c -o build/Layer5/ping.o

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
