#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../graph.h"
#include "../gluethread/glthread.h"
#include "../net.h"
#include "../utils.h"
#include "layer3.h"

// Forward declarations.
static bool _rt_table_entry_add(RtTable* rt_table, L3Route* l3_route);
void        init_rt_table(RtTable** rt_table);
L3Route*    rt_table_lookup(RtTable* rt_table, char* ip_addr, char mask);
void        clear_rt_table(RtTable* rt_table);
void        delete_rt_table_entry(RtTable* rt_table, char* ip_addr, char mask);
void        rt_table_add_route(RtTable* rt_table, char* dst, char mask,
                               char* gw, char* oif);
void        rt_table_add_direct_route(RtTable* rt_table, char* dst, char mask);
void        dump_rt_table(RtTable* rt_table);
L3Route*    l3rib_lookup_lpm(RtTable* rt_table, unsigned int dest_ip);
void        layer3_pkt_recv(Node* node, Interface* iif, char* pkt, size_t pkt_size);

// ---- routing table -------------------------------------------------------

void init_rt_table(RtTable** rt_table){
    *rt_table = calloc(1, sizeof(RtTable));
    init_glthread(&(*rt_table)->route_list);
}

// Exact-match lookup (key = dest + mask). Used by add/delete so we
// can detect duplicates and replace.
L3Route* rt_table_lookup(RtTable* rt_table, char* ip_addr, char mask){
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&rt_table->route_list, cur){
        L3Route* r = rt_glue_to_l3_route(cur);
        if(strncmp(r->dest, ip_addr, 16) == 0 && r->mask == mask){
            return r;
        }
    } ITERATE_GLTHREAD_END(&rt_table->route_list, cur);
    return 0;
}

void clear_rt_table(RtTable* rt_table){
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&rt_table->route_list, cur){
        L3Route* r = rt_glue_to_l3_route(cur);
        remove_glthread(cur);
        free(r);
    } ITERATE_GLTHREAD_END(&rt_table->route_list, cur);
}

void delete_rt_table_entry(RtTable* rt_table, char* ip_addr, char mask){
    char prefix[16];
    apply_mask(ip_addr, mask, prefix);
    L3Route* r = rt_table_lookup(rt_table, prefix, mask);
    if(!r){
        return;
    }
    remove_glthread(&r->rt_glue);
    free(r);
}

// LPM: walk the list; track the longest mask whose prefix matches
// `dest_ip` post-mask; fall back to 0.0.0.0/0 if present.
L3Route* l3rib_lookup_lpm(RtTable* rt_table, unsigned int dest_ip){
    L3Route*  lpm           = 0;
    L3Route*  default_route = 0;
    char      longest_mask  = 0;
    char      dest_ip_str[16];
    char      subnet[16];
    GlThread* cur = 0;

    inet_ntop(AF_INET, &dest_ip, dest_ip_str, 16);
    dest_ip_str[15] = '\0';

    ITERATE_GLTHREAD_BEGIN(&rt_table->route_list, cur){
        L3Route* r = rt_glue_to_l3_route(cur);
        memset(subnet, 0, sizeof(subnet));
        apply_mask(dest_ip_str, r->mask, subnet);

        if(strncmp("0.0.0.0", r->dest, 16) == 0 && r->mask == 0){
            default_route = r;
            continue;
        }
        if(strncmp(subnet, r->dest, strlen(subnet)) == 0
           && r->mask > longest_mask){
            longest_mask = r->mask;
            lpm          = r;
        }
    } ITERATE_GLTHREAD_END(&rt_table->route_list, cur);

    return lpm ? lpm : default_route;
}

void dump_rt_table(RtTable* rt_table){
    GlThread* cur = 0;
    printf("L3 Routing Table:\n");
    ITERATE_GLTHREAD_BEGIN(&rt_table->route_list, cur){
        L3Route* r = rt_glue_to_l3_route(cur);
        printf("\t%-18s %-4d %-18s %s\n",
               r->dest, r->mask,
               r->is_direct ? "NA" : r->gw_ip,
               r->is_direct ? "NA" : r->oif);
    } ITERATE_GLTHREAD_END(&rt_table->route_list, cur);
}

// Replace-or-insert. Returns false if an identical route already
// exists (caller should free the duplicate allocation).
static bool _rt_table_entry_add(RtTable* rt_table, L3Route* l3_route){
    L3Route* old = rt_table_lookup(rt_table, l3_route->dest, l3_route->mask);
    if(old && IS_L3_ROUTES_EQUAL(old, l3_route)){
        return false;
    }
    if(old){
        delete_rt_table_entry(rt_table, old->dest, old->mask);
    }
    init_glthread(&l3_route->rt_glue);
    glthread_add_next(&rt_table->route_list, &l3_route->rt_glue);
    return true;
}

void rt_table_add_direct_route(RtTable* rt_table, char* dst, char mask){
    rt_table_add_route(rt_table, dst, mask, 0, 0);
}

// Add a static route. `gw` + `oif` may be NULL/NULL for a direct
// route (then `is_direct` is set true and gw/oif slots stay empty).
//
// Idempotent: `_rt_table_entry_add` does an exact (dest+mask)
// lookup; if an identical row exists it returns false and we
// silently free the duplicate allocation. No error reported,
// because re-installing the same route is benign.
void rt_table_add_route(RtTable* rt_table, char* dst, char mask,
                        char* gw, char* oif){
    char prefix[16];
    apply_mask(dst, mask, prefix);

    L3Route* r = calloc(1, sizeof(L3Route));
    strncpy(r->dest, prefix, 16);
    r->dest[15] = '\0';
    r->mask     = mask;
    if(!gw && !oif){
        r->is_direct = true;
    } else {
        r->is_direct = false;
        strncpy(r->gw_ip, gw, 16);
        r->gw_ip[15] = '\0';
        strncpy(r->oif, oif, IF_NAME_SIZE);
        r->oif[IF_NAME_SIZE - 1] = '\0';
    }
    if(!_rt_table_entry_add(rt_table, r)){
        free(r);
    }
}

// ---- packet receive (still a stub - ch9 wires forwarding) ---------------

void layer3_pkt_recv(Node* node, Interface* iif, char* pkt, size_t pkt_size){
    printf("Layer 3 Packet Recvd : Rcv Node %s, Intf : %s, data recvd : %s, pkt size : %zu\n",
           node->node_name, iif->if_name, pkt, pkt_size);
}
