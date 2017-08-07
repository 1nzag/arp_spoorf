#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <stdint.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <netinet/ip.h>

struct packet_list
{
	u_char* data;
	uint32_t size;
	struct packet_list* next;
};

struct distribute_packet
{
	struct packet_list** packet;
};


typedef struct aTHREAD
{
	pcap_t *h;
	int num;
}targ;




extern struct in_addr* sender_list;
extern struct in_addr* target_list;
extern int spoof_num;
extern uint8_t **sender_MAC;
extern uint8_t **target_MAC;
extern uint8_t my_MAC[6];
extern uint8_t broadcast_MAC[6];

extern struct distribute_packet p_list;

#define HW_ADDR_LEN 16

#ifndef __get_mac_addr_h__
#define __get_mac_addr_h__

void get_addr(unsigned char MAC_addr[6],struct in_addr *IP_addr ,char* interface);

#endif

#ifndef __request_ARP_h__
#define __request_ARP_h__

void rs_ARP(pcap_t* handle, uint8_t MAC_addr[6],uint8_t MAC_dest_MAC[6] ,struct in_addr* IP1, struct in_addr* IP2,int mode);

#ifndef __get_senders_mac_h__
#define __get_senders_mac_h__

void get_senders_mac(pcap_t *handle, struct in_addr* sender_IP, uint8_t MAC_addr[6]);
#endif



#endif

#ifndef __mod_packet_h__
#define __mod_packet_h__
int mod_packet(u_char* mod_pointer, uint8_t my_MAC[6], uint8_t senders_MAC[6], uint8_t target_MAC[6]);

#endif

#ifndef __spoofing_h__
#define __spoofing_h__
void spoofing(void* arg);

#endif

#ifndef __distribute_packet_h__
#define __distribute_packet_h__

void distribute_packet(void* a);
#endif

#ifndef __APPEND_packet_h__
#define __APPEND_pakcet_h__

void APPEND_packet(struct distribute_packet* list, int id, struct packet_list* next);
#endif

#ifndef __destroy_packet_h__
#define __destroy_packet_h__
void destroy_packet(struct packet_list* ppacket);
#endif

#ifndef __POP_packet_h__
#define __POP_packet_h__
struct packet_list* POP_packet(struct distribute_packet* list, int id);
#endif

#ifndef __CREATE_packet_h__
#define __CREATE_pakcet_h__
struct packet_list* CREATE_packet(u_char* pointer, uint32_t size);
#endif

#ifndef __MACtos_h__
#define __MACtos_h__
char* MACtos(uint8_t MAC[6]);
#endif
