#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "../graph.h"
#include "../Layer4/tcp.h"
#include "http.h"

// Forward declarations.
static void http_hello_on_data(Tcb* tcb, const char* data, size_t len);
bool        http_hello_install(Node* node, unsigned short port);

static void http_hello_on_data(Tcb* tcb, const char* data, size_t len){
    (void)data;
    (void)len;
    static const char body[]    = "hello\n";
    static const char response[] =
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: 6\r\n"
        "Connection: close\r\n"
        "\r\n"
        "hello\n";

    printf("HTTP : %s : 200 OK -> peer\n", tcb->node->node_name);
    tcp_send_data(tcb->node, tcb->remote_ip, tcb->remote_port,
                  response, sizeof(response) - 1);
    tcp_close(tcb->node, tcb->remote_ip, tcb->remote_port);
    // body[] is referenced only as a sanity check that the
    // numerical Content-Length stays in sync.
    (void)body;
}

bool http_hello_install(Node* node, unsigned short port){
    return tcp_listen_with_handler(node, port, http_hello_on_data);
}
