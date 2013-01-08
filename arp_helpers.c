#include "my_headers.h"

arp_message* build_arp_message(int msg_type, unsigned char *sender_mac, unsigned long sender_ip, 
			     unsigned char* target_mac, unsigned long target_ip)
			     
{
	arp_message * msg_to_send;
	
	msg_to_send = malloc(sizeof(arp_message));
	memset(msg_to_send, 0, sizeof(arp_message));
	
	msg_to_send->frame_id = (MY_ARP_FRAME);
	msg_to_send->hard_type = (ARPHRD_ETHER);
	msg_to_send->prot_type = (ETH_P_IP);
	msg_to_send->prot_size = sizeof(struct in_addr);
	msg_to_send->hard_size = ETH_ALEN;
	msg_to_send->op = (msg_type); // ARPOP_REPLY or ARPOP_REQUEST
	msg_to_send->sender_ip.s_addr = sender_ip;
	msg_to_send->target_ip.s_addr = target_ip;
	memcpy(msg_to_send->sender_mac, sender_mac, ETH_ALEN);
	if (target_mac != NULL)
		memcpy(msg_to_send->target_mac, target_mac, ETH_ALEN);
	
	//printf("called with src-ip %ld, dest-ip %ld\n", (sender_ip), (target_ip));
	//printf("build_arp_message src-ip %d, dest-ip %d\n", (msg_to_send->sender_ip).s_addr, (msg_to_send->target_ip).s_addr);
	//printf("ending of build_arp_message\n()");
	return msg_to_send;    
}

void printARPMessage(arp_message* data)
{
	//printf("frame id %d\t op %d\t sender-mac %s\t sender-ip %s\t target-mac %s\t target-ip %s\n", data->frame_id,data->op,
	//       print_mac_address(data->sender_mac), inet_ntoa(data->sender_ip), print_mac_address(data->target_mac), inet_ntoa(data->target_ip));
	printf("ARP Frame ID: %d\n", data->frame_id);
	printf("ARP Message Type: %s\n", (data->op == ARPOP_REPLY) ? "REPLY" : "REQUEST");
	printf("ARP Sender MAC address %s\n", print_mac_address(data->sender_mac));
	printf("ARP Sender IP address %s\n", inet_ntoa(data->sender_ip));
	printf("ARP Target MAC address %s\n", print_mac_address(data->target_mac));
	printf("ARP Target IP address %s\n", inet_ntoa(data->target_ip));	
}

void* buildNewFrame(unsigned char* dest_mac, unsigned char* src_mac, short proto ,int interface_index,
		    struct sockaddr_ll* socket_addr,arp_message* data, my_bool broadcast_this)
{
	unsigned char bcast_mac[6]; 
	void* buffer;
	int toCopy, i;
	
	for(i = 0; i < 6; i++)
		bcast_mac[i] = 0xff;
	
	/*prepare sockaddr_ll*/

	/*RAW communication*/
	socket_addr->sll_family   = PF_PACKET;	

	/*index of the network device
	see full code later how to retrieve it*/
	
	socket_addr->sll_ifindex  = interface_index;

	/*ARP hardware identifier is ethernet*/
	socket_addr->sll_hatype   = ARPHRD_ETHER;

	if (broadcast_this == my_true)
	{
		socket_addr->sll_pkttype = PACKET_BROADCAST;
		/*address length*/
		socket_addr->sll_halen    = ETH_ALEN;		
		/*MAC - begin*/
		socket_addr->sll_addr[0]  = bcast_mac[0];		
		socket_addr->sll_addr[1]  = bcast_mac[1];		
		socket_addr->sll_addr[2]  = bcast_mac[2];
		socket_addr->sll_addr[3]  = bcast_mac[3];
		socket_addr->sll_addr[4]  = bcast_mac[4];
		socket_addr->sll_addr[5]  = bcast_mac[5];		
	}
	else if (broadcast_this == my_false)
	{
		/*target is another host*/
		socket_addr->sll_pkttype  = PACKET_OTHERHOST;

		/*address length*/
		socket_addr->sll_halen    = ETH_ALEN;		
		/*MAC - begin*/
		socket_addr->sll_addr[0]  = dest_mac[0];		
		socket_addr->sll_addr[1]  = dest_mac[1];		
		socket_addr->sll_addr[2]  = dest_mac[2];
		socket_addr->sll_addr[3]  = dest_mac[3];
		socket_addr->sll_addr[4]  = dest_mac[4];
		socket_addr->sll_addr[5]  = dest_mac[5];
	}
	/*MAC - end*/
	socket_addr->sll_addr[6]  = 0x00;/*not used*/
	socket_addr->sll_addr[7]  = 0x00;/*not used*/
	
	buffer = (void*)malloc(ETH_FRAME_LEN);
	memset(buffer, 0, ETH_FRAME_LEN);
	
	if (broadcast_this == my_true)
		memcpy((void*)buffer, (void*)bcast_mac, ETH_ALEN);
	else if (broadcast_this == my_false)
		memcpy((void*)buffer, (void*)dest_mac, ETH_ALEN);
	
	memcpy((void*)(buffer+ETH_ALEN), (void*)src_mac, ETH_ALEN);
	memcpy((void*)(buffer+ETH_ALEN+ETH_ALEN), &proto, sizeof(short));
	
	//printf("printing before sending\n");

	printf("---------------------------------------------------------------\n");
	printf("ARP: Sending ethernet frame with contents below: \n");
	printf("Ethernet Dest MAC : %s\n", (broadcast_this == my_true) ? print_mac_address(bcast_mac) : print_mac_address(dest_mac));
	printf("Ethernet Src MAC : %s\n", print_mac_address(src_mac));
	printf("Ethernet Protocol ID : %d\n", MY_PROTO_ID);
	printARPMessage(data);
	//printf("printing over\n");

	printf("---------------------------------------------------------------\n");
	memcpy((void*)(buffer+ETH_ALEN+ETH_ALEN+sizeof(short)), data, sizeof(arp_message)); 
	
	return buffer;
}

void sendFrame(int sockfd, void* eframe, struct sockaddr_ll* socket_address)
{
	int send_result;
	send_result = 0;
	
	if(eframe != NULL)
	{

		send_result = sendto(sockfd,eframe, ETH_FRAME_LEN, 0,(struct sockaddr*)socket_address, sizeof(struct sockaddr_ll));
		free(eframe);
		if (send_result == -1) 
		{
			printf("Error sending ethernet frame.\n");
			exit(-1);
		}
		//printf("sendframe sent %d bytes\n", send_result);
	}
	else
		printf("Frame is empty!!\n");
}

arp_cache_entry* remove_stale_entries_from_arp_cache(arp_cache_entry* head)
{
        struct arp_cache_entry *to_be_deleted;
        struct arp_cache_entry *traverse_node = head;
        struct arp_cache_entry *previous_node = NULL;
        unsigned char mac_address[6];
        int i;

		for(i = 0; i < 6; i++)
			mac_address[i] = 0x00;

        while((traverse_node!=NULL) && (memcmp(mac_address, traverse_node->mac_address, 6) == 0))
        {
                to_be_deleted = traverse_node;
                traverse_node = traverse_node->next;
                previous_node = traverse_node;
                //free(to_be_deleted);
        }
        if(traverse_node == NULL)
        {
                head = NULL;
                return NULL;
        }
        previous_node = traverse_node;
        head = previous_node;
        traverse_node = traverse_node->next;
        while(traverse_node != NULL)
        {
                if((memcmp(mac_address, traverse_node->mac_address, 6) == 0))
                {
                        to_be_deleted = traverse_node;
                        previous_node->next = traverse_node->next;
                        //free(to_be_deleted);
                        traverse_node = previous_node->next;
                }
                else
                {
                        traverse_node = traverse_node->next;
                        previous_node = previous_node->next;
                }
        }       

        return head;
}

my_ether_hdr* get_ethernet_hdr(void *buffer)
{
	my_ether_hdr *received_hdr;
	received_hdr = NULL;
	
	if (buffer != NULL)
	{
		received_hdr = malloc(sizeof(my_ether_hdr));
		memset(received_hdr, 0, sizeof(my_ether_hdr));
	
		memcpy(received_hdr, buffer, sizeof(my_ether_hdr));
	}
	return received_hdr;
}

arp_message* get_ethernet_payload(void *buffer)
{
	arp_message* received_payload;
	received_payload = NULL;
	
	if(buffer != NULL)
	{
		received_payload = malloc(sizeof(arp_message));
		memset(received_payload, 0, sizeof(arp_message));
		
		memcpy(received_payload, buffer, sizeof(arp_message));
	}
	return received_payload;
}

char* print_mac_address(unsigned char* mac_addr)
{
	char *address;
	int i,j;
	
	address = malloc(19);
	memset(address, 0, 19);
	
	for(i = 0, j = 0; i < 6; i++, j=j+3)
	{
		if (i == 5)
			sprintf(address+j, "%02x", mac_addr[i]);
		else
			sprintf(address+j, "%02x:", mac_addr[i]);
	}
	
	return address;
}

char * my_sock_ntop(const struct sockaddr *sa, socklen_t salen)
{
    char portstr[8];
    static char str[128];
    struct sockaddr_in *sin;

        switch (sa->sa_family) 
        {
                case AF_INET: 
                {
                        sin = (struct sockaddr_in *) sa;

                        if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL)
                                return(NULL);
                        if (ntohs(sin->sin_port) != 0) 
                        {
                                snprintf(portstr, sizeof(portstr), ":%d", ntohs(sin->sin_port));
                                strcat(str, portstr);
                        }
                        return(str);
                }
        }
}

void print_arp_cache(arp_cache_entry *head)
{
	arp_cache_entry* traverse_node;
	
	traverse_node = head;
	
	if(traverse_node != NULL)
	{
		printf("-------------- ARP CACHE -------------- \n");
		printf("IP-Address\tHardware-Address\tIndex\tType\tClient-Socket\n");
		while(traverse_node != NULL)
		{
			printf("%s\t%s\t%d\t%d\t%d\n", inet_ntoa(traverse_node->ip_address), print_mac_address(traverse_node->mac_address),
			       traverse_node->sll_ifindex, traverse_node->sll_hatype, traverse_node->domain_sockfd);

			traverse_node = traverse_node->next;
		}
		printf("-------------- ARP CACHE -------------- \n");
	}
	else
	{
		printf("ARP Cache Empty!\n");
	}	
}

arp_cache_entry* createARPCacheEntry(unsigned long ip, unsigned char* neighbour_mac, int interface_index, unsigned short hw_type, int domain_sockfd)
{
	arp_cache_entry *new_entry;
	new_entry = malloc(sizeof(arp_cache_entry));
	memset(new_entry, 0, sizeof(arp_cache_entry));
	
	new_entry->ip_address.s_addr = ip;
	new_entry->sll_ifindex = interface_index;
	new_entry->sll_hatype = hw_type;
	new_entry->domain_sockfd = domain_sockfd;
	memcpy(new_entry->mac_address, neighbour_mac, ETH_ALEN);
	new_entry->next = NULL;
	
	return new_entry;
}

arp_cache_entry* getARPCacheEntry(arp_cache_entry* head, unsigned long ip)
{
	arp_cache_entry* traverse_node;
	
	traverse_node = head;
	
	while (traverse_node != NULL)
	{
		if((traverse_node->ip_address.s_addr == ip))
		{
			return traverse_node;
		}
		
		traverse_node = traverse_node->next;
	}
	
	return NULL;
}

my_bool updateARP_Reply_CacheTable(arp_cache_entry* head, unsigned long ip, unsigned char* mac_address, int interface_index, unsigned short hw_type)
{
	arp_cache_entry* traverse_node;
	int found;
	
	traverse_node = head;
	found = -1;
	while(traverse_node != NULL)
	{
		if((traverse_node->ip_address.s_addr == ip))
		{
			traverse_node->sll_ifindex = interface_index;
			traverse_node->sll_hatype = hw_type;
			memcpy(&(traverse_node->mac_address), mac_address, ETH_ALEN);
			found = 1;
		}
		traverse_node= traverse_node->next;
	}
	
	if (found == 1)
		return my_true;
	else
		return my_false;
		
}

my_bool updateARPCacheTable(arp_cache_entry* head, unsigned long ip, unsigned char* mac_address, int interface_index, unsigned short hw_type)
{
	arp_cache_entry* traverse_node;
	int found;
	
	traverse_node = head;
	found = -1;
	while(traverse_node != NULL)
	{
		if((traverse_node->ip_address.s_addr == ip) && (memcmp(&(traverse_node->mac_address), mac_address, ETH_ALEN) == 0))
		{
			traverse_node->sll_ifindex = interface_index;
			traverse_node->sll_hatype = hw_type;
			found = 1;
		}
		traverse_node= traverse_node->next;
	}
	
	if (found == 1)
		return my_true;
	else
		return my_false;
		
}

arp_cache_entry* addOrUpdateARPCacheTable(arp_cache_entry* head, arp_cache_entry* nodeToAdd)
{
	arp_cache_entry* traverse_node;
	int found;
	
	traverse_node = head;
	found = -1;
	while(traverse_node != NULL)
	{
		if((traverse_node->ip_address.s_addr == nodeToAdd->ip_address.s_addr) && (memcmp(&(traverse_node->mac_address), &(nodeToAdd->mac_address), ETH_ALEN) == 0))
		{
			traverse_node->sll_ifindex = nodeToAdd->sll_ifindex;
			traverse_node->sll_hatype = nodeToAdd->sll_hatype;
			traverse_node->domain_sockfd = nodeToAdd->domain_sockfd;
			found = 1;
		}
		traverse_node= traverse_node->next;
	}
	
	if (found == 1)
		return head;
	else
	{
		traverse_node = head;
		if(traverse_node == NULL)
		{
			head = nodeToAdd;
			return head;
		}
		else
		{
			while(traverse_node->next != NULL)
			{
				traverse_node = traverse_node->next;
			}
			
			traverse_node->next = nodeToAdd;
			return head;
		}
	}
}

my_bool staleCacheEntrySocket(arp_cache_entry* head, unsigned long ip, unsigned char* mac_to_compare)
{
	arp_cache_entry* traverse_node;
	int found;
	
	traverse_node = head;
	found = -1;
	while(traverse_node != NULL)
	{
		if((traverse_node->ip_address.s_addr == ip) && (memcmp(&(traverse_node->mac_address), mac_to_compare, ETH_ALEN) == 0))
		{	
			traverse_node->domain_sockfd = -1;
			found = 1;
		}
		traverse_node = traverse_node->next;	
	}
	
	if (found == 1)
		return my_true;
	else
		return my_false;
}
