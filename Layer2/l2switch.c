#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../comm.h"
#include "../graph.h"
#include "../gluethread/glthread.h"
#include "../net.h"
#include "../utils.h"
#include "layer2.h"

// Forward declarations.
static void           l2_switch_perform_mac_learning(Node* node, char* src_mac, char* if_name);
static void           l2_switch_forward_frame(Node* node, Interface* recv_intf, char* pkt, size_t pkt_size);
void                  init_mac_table(MacTable** mac_table);
MacTableEntry*        mac_table_lookup(MacTable* mac_table, char* mac);
void                  clear_mac_table(MacTable* mac_table);
void                  delete_mac_table_entry(MacTable* mac_table, char* mac);
bool                  mac_table_entry_add(MacTable* mac_table, MacTableEntry* entry);
void                  dump_mac_table(MacTable* mac_table);
void                  l2_switch_recv_frame(Interface* iif, char* pkt, size_t pkt_size);

// ---- mac table CRUD ------------------------------------------------------

void init_mac_table(MacTable** mac_table){
    *mac_table = calloc(1, sizeof(MacTable));
    init_glthread(&(*mac_table)->mac_entries);
}

MacTableEntry* mac_table_lookup(MacTable* mac_table, char* mac){
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&mac_table->mac_entries, cur){
        MacTableEntry* e = mac_entry_glue_to_mac_entry(cur);
        if(strncmp((char*)e->mac.mac, mac, sizeof(MacAddr)) == 0){
            return e;
        }
    } ITERATE_GLTHREAD_END(&mac_table->mac_entries, cur);
    return 0;
}

void clear_mac_table(MacTable* mac_table){
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&mac_table->mac_entries, cur){
        MacTableEntry* e = mac_entry_glue_to_mac_entry(cur);
        remove_glthread(cur);
        free(e);
    } ITERATE_GLTHREAD_END(&mac_table->mac_entries, cur);
}

void delete_mac_table_entry(MacTable* mac_table, char* mac){
    MacTableEntry* e = mac_table_lookup(mac_table, mac);
    if(!e){
        return;
    }
    remove_glthread(&e->mac_entry_glue);
    free(e);
}

#define IS_MAC_TABLE_ENTRY_EQUAL(a, b)                                    \
    (strncmp((char*)(a)->mac.mac, (char*)(b)->mac.mac, sizeof(MacAddr)) == 0 && \
     strncmp((a)->oif_name, (b)->oif_name, IF_NAME_SIZE) == 0)

bool mac_table_entry_add(MacTable* mac_table, MacTableEntry* entry){
    MacTableEntry* old = mac_table_lookup(mac_table, (char*)entry->mac.mac);
    if(old && IS_MAC_TABLE_ENTRY_EQUAL(old, entry)){
        return false;
    }
    if(old){
        delete_mac_table_entry(mac_table, (char*)old->mac.mac);
    }
    init_glthread(&entry->mac_entry_glue);
    glthread_add_next(&mac_table->mac_entries, &entry->mac_entry_glue);
    return true;
}

void dump_mac_table(MacTable* mac_table){
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&mac_table->mac_entries, cur){
        MacTableEntry* e = mac_entry_glue_to_mac_entry(cur);
        printf("\tMAC : %u:%u:%u:%u:%u:%u   | Intf : %s\n",
               e->mac.mac[0], e->mac.mac[1], e->mac.mac[2],
               e->mac.mac[3], e->mac.mac[4], e->mac.mac[5],
               e->oif_name);
    } ITERATE_GLTHREAD_END(&mac_table->mac_entries, cur);
}

// ---- mac learning + forwarding -------------------------------------------

// Learning: stamp (src_mac, if_name) into the switch's table. If
// the entry already exists with the same OIF, free the duplicate.
static void l2_switch_perform_mac_learning(Node* node, char* src_mac, char* if_name){
    MacTableEntry* e = calloc(1, sizeof(MacTableEntry));
    memcpy(e->mac.mac, src_mac, sizeof(MacAddr));
    strncpy(e->oif_name, if_name, IF_NAME_SIZE);
    e->oif_name[IF_NAME_SIZE - 1] = '\0';
    if(!mac_table_entry_add(NODE_MAC_TABLE(node), e)){
        free(e);
    }
}

// Forwarding: broadcast dst -> flood (except recv intf). Known
// unicast -> send out the learned OIF. Unknown unicast -> flood.
static void l2_switch_forward_frame(Node* node, Interface* recv_intf,
                                    char* pkt, size_t pkt_size){
    EthernetHdr* eth = (EthernetHdr*)pkt;

    if(IS_MAC_BROADCAST_ADDR((char*)eth->dst_mac.mac)){
        send_pkt_flood(node, recv_intf, pkt, pkt_size);
        return;
    }
    MacTableEntry* e = mac_table_lookup(NODE_MAC_TABLE(node), (char*)eth->dst_mac.mac);
    if(!e){
        send_pkt_flood(node, recv_intf, pkt, pkt_size);
        return;
    }
    Interface* oif = get_node_if_by_name(node, e->oif_name);
    if(!oif){
        return;
    }
    send_pkt_out(pkt, pkt_size, oif);
}

void l2_switch_recv_frame(Interface* iif, char* pkt, size_t pkt_size){
    Node*        node = iif->att_node;
    EthernetHdr* eth  = (EthernetHdr*)pkt;
    l2_switch_perform_mac_learning(node, (char*)eth->src_mac.mac, iif->if_name);
    l2_switch_forward_frame(node, iif, pkt, pkt_size);
}
