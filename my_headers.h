#include <sys/socket.h>
#include <sys/un.h>
#include <netdb.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <limits.h>
#include <errno.h>
#include "hw_addrs.h"

#define MY_PROTO_ID 0x8885
#define MY_ARP_FRAME 0x8888

#define LISTEN_QUEUE 10

#ifndef MAX
        #define MAX( a, b ) ( ((a) > (b)) ? (a) : (b) )
#endif

#define ARP_SUN_PATH "my_arp_path"

#define my_bool int
#define my_true 1
#define my_false 0

typedef struct arp_cache_entry{
	struct in_addr ip_address;
	unsigned char mac_address[6];
	int sll_ifindex;
	unsigned short sll_hatype;
	int domain_sockfd;
	struct arp_cache_entry* next;
}arp_cache_entry;

typedef struct arp_message{
    unsigned short frame_id;
    unsigned short hard_type;
    unsigned short prot_type;
    unsigned char hard_size;
    unsigned char prot_size;
    unsigned short op;
    unsigned char sender_mac[ETH_ALEN];
    struct in_addr sender_ip;
    unsigned char target_mac[ETH_ALEN];
    struct in_addr target_ip;
}arp_message;


typedef struct my_ether_hdr 
{
	unsigned char dest_mac[6];
	unsigned char src_mac[6];
	short proto;
}my_ether_hdr;

typedef struct ethernet_frame
{
	my_ether_hdr eth_header;
	arp_message eth_data;
}ethernet_frame;

typedef struct hwaddr {
	int             sll_ifindex;	 /* Interface number */
	unsigned short  sll_hatype;	 /* Hardware type */
	unsigned char   sll_halen;		 /* Length of address */
	unsigned char   sll_addr[8];	 /* Physical layer address */
}hwaddr;

typedef struct api_serialized_data {
	struct sockaddr_in ip_addr;
	struct hwaddr HWaddr;
}api_serialized_data;


int areq (struct sockaddr *IPaddr, socklen_t sockaddrlen, struct hwaddr *HWaddr);


arp_message* build_arp_message(int msg_type, unsigned char *sender_mac, unsigned long sender_ip, 
			     unsigned char* target_mac, unsigned long target_ip);
void* buildNewFrame(unsigned char* dest_mac, unsigned char* src_mac, short proto ,int interface_index,
		    struct sockaddr_ll* socket_addr,arp_message* data, my_bool broadcast_this);
void sendFrame(int sockfd, void* eframe, struct sockaddr_ll* socket_address);
my_ether_hdr* get_ethernet_hdr(void *buffer);
arp_message* get_ethernet_payload(void *buffer);
char* print_mac_address(unsigned char* mac_addr);
char * my_sock_ntop(const struct sockaddr *sa, socklen_t salen);
void print_arp_cache(arp_cache_entry *head);
arp_cache_entry* createARPCacheEntry(unsigned long ip, unsigned char* neighbour_mac, int interface_index, unsigned short hw_type, int domain_sockfd);
arp_cache_entry* getARPCacheEntry(arp_cache_entry* head, unsigned long ip);
my_bool updateARPCacheTable(arp_cache_entry* head, unsigned long ip, unsigned char* mac_address, int interface_index, unsigned short hw_type);
arp_cache_entry* addOrUpdateARPCacheTable(arp_cache_entry* head, arp_cache_entry* nodeToAdd);
my_bool staleCacheEntrySocket(arp_cache_entry* head, unsigned long ip, unsigned char* mac_to_compare);


