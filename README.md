# SamTCPIP

A from-scratch TCP/IP stack in C.

## Layout

```
graph.h / graph.c       generic in-memory graph (Node / Link / Interface)
gluethread/             intrusive doubly-linked list used everywhere
topologies.c            canned topologies for smoke tests
testapp.c               minimal CLI driver for the build
Makefile / build.sh     build wiring
tests/                  bash E2E tests, one per chapter
docs/NN-topic.md        rationale + gotchas, one per chapter
```

## Build + test

```
./build.sh
bash tests/run-all.sh
```
