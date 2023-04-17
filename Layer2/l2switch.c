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
static void           l2_switch_forward_frame(Node* node, Interface* recv_intf, EthernetHdr* eth, size_t pkt_size);
static bool           l2_switch_send_pkt_out(char* pkt, size_t pkt_size, Interface* oif);
static void           l2_switch_flood_pkt_out(Node* node, Interface* exempted_intf, char* pkt, size_t pkt_size);
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

// ch35: monotonic ms helper for aging.
#include <time.h>
static long mac_now_ms(void){
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000L + (long)ts.tv_nsec / 1000000L;
}

MacTableEntry* mac_table_lookup(MacTable* mac_table, char* mac){
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&mac_table->mac_entries, cur){
        MacTableEntry* e = mac_entry_glue_to_mac_entry(cur);
        if(strncmp((char*)e->mac.mac, mac, sizeof(MacAddr)) == 0){
            e->last_seen_ms = mac_now_ms();   // ch35: refresh on hit
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
    entry->last_seen_ms = mac_now_ms();    // ch35: stamp on install
    glthread_add_next(&mac_table->mac_entries, &entry->mac_entry_glue);
    return true;
}

// ch35: walk + remove stale MAC entries.
int mac_age(MacTable* mac_table, long threshold_ms){
    if(!mac_table || threshold_ms < 0) return 0;
    long now = mac_now_ms();
    int removed = 0;
    GlThread* cur = 0;
    ITERATE_GLTHREAD_BEGIN(&mac_table->mac_entries, cur){
        MacTableEntry* e = mac_entry_glue_to_mac_entry(cur);
        long age = now - e->last_seen_ms;
        if(age < threshold_ms) continue;
        printf("MAC age : timeout age=%ldms (threshold=%ldms)\n",
               age, threshold_ms);
        remove_glthread(cur);
        free(e);
        removed++;
    } ITERATE_GLTHREAD_END(&mac_table->mac_entries, cur);
    return removed;
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

// ch7: per-port egress decision. Returns true if the frame was sent
// out, false if dropped. The egress rules:
//   - ACCESS port, no VLAN, untagged frame -> forward untouched.
//   - ACCESS port, has VLAN, untagged frame -> drop (case 2).
//   - ACCESS port, has VLAN X, tagged X     -> UNTAG and forward.
//     (Deviation from reference: ref forwards tagged. Real switches
//      untag on ACCESS egress so the host receives a plain frame;
//      our L3 qualifier rejects tagged frames so untag is required
//      for end-to-end ARP to work.)
//   - ACCESS port, has VLAN X, tagged Y!=X  -> drop.
//   - ACCESS port, no VLAN, tagged frame    -> drop.
//   - TRUNK port, tagged frame in member VLAN -> forward as-is.
//   - TRUNK port, tagged but not a member, or untagged -> drop.
static bool l2_switch_send_pkt_out(char* pkt, size_t pkt_size, Interface* oif){
    assert(!IS_INTF_L3_MODE(oif));
    if(IF_L2_MODE(oif) == L2_MODE_UNKNOWN){
        return false;
    }

    EthernetHdr*  eth = (EthernetHdr*)pkt;
    Vlan8021qHdr* tag = is_pkt_vlan_tagged(eth);

    if(IF_L2_MODE(oif) == ACCESS){
        unsigned int port_vlan = get_access_intf_operating_vlan_id(oif);
        if(port_vlan == 0 && !tag){
            send_pkt_out(pkt, pkt_size, oif);
            return true;
        }
        if(port_vlan == 0 && tag){
            return false;
        }
        if(!tag){
            return false;
        }
        if(GET_802_1Q_VLAN_ID(tag) != port_vlan){
            return false;
        }
        // Untag in place, then send.
        size_t new_size = untag_pkt_with_vlan_id(eth, pkt_size);
        send_pkt_out((char*)eth, new_size, oif);
        return true;
    }

    if(IF_L2_MODE(oif) == TRUNK){
        if(!tag){
            return false;
        }
        if(!is_trunk_interface_vlan_enabled(oif, GET_802_1Q_VLAN_ID(tag))){
            return false;
        }
        send_pkt_out(pkt, pkt_size, oif);
        return true;
    }
    return false;
}

// VLAN-aware flood: walk every interface (skipping the recv port)
// and let l2_switch_send_pkt_out decide whether the frame fits this
// port's VLAN config.
static void l2_switch_flood_pkt_out(Node* node, Interface* exempted_intf,
                                    char* pkt, size_t pkt_size){
    for(int i = 0; i < MAX_INTF_PER_NODE; i++){
        Interface* oif = node->intf[i];
        if(!oif){
            break;
        }
        if(oif == exempted_intf){
            continue;
        }
        l2_switch_send_pkt_out(pkt, pkt_size, oif);
    }
}

// Forwarding: broadcast dst -> VLAN-aware flood. Known unicast ->
// VLAN-aware send out the learned OIF. Unknown unicast -> flood.
static void l2_switch_forward_frame(Node* node, Interface* recv_intf,
                                    EthernetHdr* eth, size_t pkt_size){
    if(IS_MAC_BROADCAST_ADDR((char*)eth->dst_mac.mac)){
        l2_switch_flood_pkt_out(node, recv_intf, (char*)eth, pkt_size);
        return;
    }
    MacTableEntry* e = mac_table_lookup(NODE_MAC_TABLE(node), (char*)eth->dst_mac.mac);
    if(!e){
        l2_switch_flood_pkt_out(node, recv_intf, (char*)eth, pkt_size);
        return;
    }
    Interface* oif = get_node_if_by_name(node, e->oif_name);
    if(!oif){
        return;
    }
    l2_switch_send_pkt_out((char*)eth, pkt_size, oif);
}

void l2_switch_recv_frame(Interface* iif, char* pkt, size_t pkt_size){
    Node*        node = iif->att_node;
    EthernetHdr* eth  = (EthernetHdr*)pkt;
    l2_switch_perform_mac_learning(node, (char*)eth->src_mac.mac, iif->if_name);
    l2_switch_forward_frame(node, iif, eth, pkt_size);
}
