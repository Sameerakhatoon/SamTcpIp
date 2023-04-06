#ifndef SAMTCPIP_HTTP_H
#define SAMTCPIP_HTTP_H

// ch29: minimal HTTP responder. Installs as a TCP on_data
// handler. On any inbound data, replies with HTTP/1.0 200 OK
// + a tiny body, then initiates orderly close.
//
// Not RFC-complete - we don't parse the request line, don't
// honour Connection: keep-alive, don't handle multi-segment
// requests. Enough to demonstrate the Milestone 2 goal:
// curl http://<our-tap-ip>:<port>/ returns "hello".

#include <stdbool.h>
#include "../graph.h"

// Install the HTTP responder on (node, port). Returns false if
// the port is already in use.
bool http_hello_install(Node* node, unsigned short port);

#endif
