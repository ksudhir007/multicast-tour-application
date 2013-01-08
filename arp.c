#include "my_headers.h"

struct hwa_info *hwahead = NULL;
struct hwa_info *canonical_head = NULL;
struct hwa_info *hwa = NULL;
arp_cache_entry *arp_cache_head = NULL;
char my_canonical_ip[INET_ADDRSTRLEN];

void build_interface_list()
{
	struct sockaddr	*sa;
	char* isAlias;
	
	
	hwa = hwahead = Get_hw_addrs();
	
	printf("****************** INTERFACE INFO *******************************\n");
	
	while(hwa != NULL)
	{
		if (strcmp(hwa->if_name, "eth0") == 0)
		{
			canonical_head = hwa;
			if (hwa->ip_alias == IP_ALIAS)
				isAlias = "Yes";
			else
				isAlias = "No";
			if ((sa = hwa->ip_addr) != NULL)
			{
				printf("Name\tIP-Address\tAlias?\tIndex\tHardware Address\n");
				printf("%s\t%s\t%s\t%d\t%s\n", hwa->if_name, (char *)my_sock_ntop(sa, sizeof(*sa)), isAlias,
				hwa->if_index, print_mac_address(hwa->if_haddr));
				if (((hwa->ip_alias) != IP_ALIAS))
					sprintf(my_canonical_ip, "%s", (char *)my_sock_ntop(sa, sizeof(*sa)));
			}
			
		}
		hwa = hwa->hwa_next;
	}
	
	printf("*****************************************************************\n");
}

void processDomainSocketData(int sock_fd, int pf_sockfd)
{
	size_t nbytes;
	fd_set service_set;
	api_serialized_data to_recv_data;
	arp_message* to_send;
	void* buffer;
	struct sockaddr_ll socket_address;
	arp_cache_entry* new_entry;
	arp_cache_entry* to_find;
	api_serialized_data to_send_data;
	
	memset(&to_recv_data, 0, sizeof(api_serialized_data));
	memset(&to_send_data, 0, sizeof(api_serialized_data));
	
	for(;;)
	{		
		FD_ZERO(&service_set);
		FD_SET(sock_fd ,&service_set);

		nbytes = select(sock_fd + 1, &service_set, NULL, NULL, NULL);
		if (nbytes < 0)
		{
			if (errno == EINTR)
				continue;
			else
			{
				perror("On select() after accepting connection from domain socket ");
				return;
			}
		}
		if(FD_ISSET(sock_fd, &service_set))
		{
			memset(&to_recv_data, 0, sizeof(api_serialized_data));
			//printf("after memset\n");
			nbytes = read(sock_fd, (void*)&to_recv_data, sizeof(api_serialized_data));
			if (nbytes == 0)
			{
				printf("ARP: Detected socket closed by areq(). Removing unknown entries from ARP Cache\n");
				//arp_cache_head = (arp_cache_entry*) remove_stale_entries_from_arp_cache(arp_cache_head);
				//staleCacheEntrySocket(arp_cache_head, to_recv_data.ip_addr.sin_addr.s_addr, to_recv_data.HWaddr.sll_addr);
				// Remove all items in linked list with mac address 00:00:00:00:00:00

				close(sock_fd);
				break;
			}
			else if(nbytes > 0)
			{
				// lookup in cache if the ip address exists.
				//printf("read %d bytes, looking for %s\n", nbytes, inet_ntoa(to_recv_data.ip_addr.sin_addr));				
				to_find = (arp_cache_entry*)getARPCacheEntry(arp_cache_head, to_recv_data.ip_addr.sin_addr.s_addr);
				if (to_find == NULL)
				{
					new_entry = createARPCacheEntry(to_recv_data.ip_addr.sin_addr.s_addr,
									to_recv_data.HWaddr.sll_addr,
									canonical_head->if_index,
									to_recv_data.HWaddr.sll_hatype,
									sock_fd);
					//printf("after createARPCacheEntry\n");
					arp_cache_head = (arp_cache_entry*)addOrUpdateARPCacheTable(arp_cache_head, new_entry);
					//printf("after addOrUpdateARPCacheTable()\n");
					
					//print_arp_cache(arp_cache_head);
					//if it does not exist. broadcast using pf packet.
					to_send = (arp_message*)build_arp_message(ARPOP_REQUEST,
										canonical_head->if_haddr,
										inet_addr(my_canonical_ip),
										NULL,
										inet_addr(inet_ntoa(to_recv_data.ip_addr.sin_addr)));
					
					//printf("after build_arp_message()\n");
					buffer = buildNewFrame(NULL, canonical_head->if_haddr, htons(MY_PROTO_ID),
							       canonical_head->if_index, &socket_address, to_send, my_true);
					//printf("after buildNewFrame\n");
					sendFrame(pf_sockfd, buffer, &socket_address);
					//printf("after sendFrame\n");

					//printf("ARP:Sending ARP request \n");
					//printARPMessage()

					return;
				}
				else
				{
					to_send_data.ip_addr.sin_addr.s_addr = to_find->ip_address.s_addr;
					to_send_data.HWaddr.sll_ifindex = to_find->sll_ifindex;
					to_send_data.HWaddr.sll_hatype = to_find->sll_hatype;
					to_send_data.HWaddr.sll_halen = ETH_ALEN;
					memcpy(to_send_data.HWaddr.sll_addr, to_find->mac_address, ETH_ALEN);
					
					nbytes =  write(sock_fd, (void*)&to_send_data, sizeof(to_send_data));
					if (nbytes < 0)
					{
						perror("On write() back to the api ");
						exit(-1);
					}
					close(to_find->domain_sockfd);
					staleCacheEntrySocket(arp_cache_head, to_find->ip_address.s_addr, to_find->mac_address);
					//close(sock_fd);
					//printf("Wrote %d bytes out of %d bytes\n", nbytes, sizeof(to_send_data));
					//printf("socket wrote areq with %s, interface %d, htype %d, hlen %d, ", inet_ntoa(to_send_data.ip_addr.sin_addr),
					//to_send_data.HWaddr.sll_ifindex, to_send_data.HWaddr.sll_hatype, to_send_data.HWaddr.sll_halen);
					//printf("%s-------\n",print_mac_address(to_send_data.HWaddr.sll_addr));					
					return;
				}
			}
		}
	}
}

void processReceivedEthernetFrame(int sockfd, my_ether_hdr *received_hdr, arp_message* received_payload, struct sockaddr_ll *socket_address)
{
	arp_cache_entry* req_dest_update;
	arp_message* to_send;
	void* buffer;
	my_bool update_status;
	struct sockaddr_ll new_socket_address;
	arp_cache_entry* to_find;
	int nbytes;
	api_serialized_data to_send_data;
	
	memset(&to_send_data, 0, sizeof(api_serialized_data));	
	
	if ((received_payload->frame_id) == MY_ARP_FRAME)
	{
		if ((received_payload->op) == ARPOP_REQUEST)
		{
			if(inet_addr(my_canonical_ip) == (received_payload->target_ip.s_addr))
			{
				printf("_______________________________________________________________\n");
				printf("ARP: I am the responding node. I received REQUEST frame with below contents : \n");
				printf("Ethernet Dest MAC : %s\n", print_mac_address(received_hdr->dest_mac));
				printf("Ethernet Src MAC : %s\n", print_mac_address(received_hdr->src_mac));
				printf("Ethernet Protocol ID : %d\n", MY_PROTO_ID);				
				printARPMessage(received_payload);
				printf("_______________________________________________________________\n");
				// create or update the cache entry by matching <source ip,  src mac address>
				// send ARP_REPLY by putting the frame_type field back and swapping 2 source addresses with 2 target addresses
				req_dest_update = createARPCacheEntry((received_payload->sender_ip.s_addr), 
						    received_payload->sender_mac,socket_address->sll_ifindex,
						    (received_payload->hard_type), -1); // ************** -1 sockfd ??
				
				arp_cache_head = (arp_cache_entry*)addOrUpdateARPCacheTable(arp_cache_head, req_dest_update);
				
				to_send = (arp_message*)build_arp_message(ARPOP_REPLY,canonical_head->if_haddr,
						  inet_addr(my_canonical_ip), received_payload->sender_mac,
						  (received_payload->sender_ip.s_addr));
				buffer = buildNewFrame(received_payload->sender_mac,canonical_head->if_haddr,htons(MY_PROTO_ID),
						       canonical_head->if_index,&new_socket_address,to_send,my_false); //received_payload->sender_mac
				sendFrame(sockfd, buffer, &new_socket_address);
				
				//printf("my frame request received, reply sent\n");
				
			}
			else
			{
				// if entry is present update it if needed,
				// if entry is not present dont do anything. update method below will take care of both
				update_status = updateARPCacheTable(arp_cache_head, (received_payload->sender_ip.s_addr),
								    received_payload->sender_mac,socket_address->sll_ifindex,
								    (received_payload->hard_type)); 
			}
		}
		else if ((received_payload->op) == ARPOP_REPLY)
		{	
			// send to client by using cache table socket descriptor
			// close client socket and stale it out in cache
			update_status = updateARP_Reply_CacheTable(arp_cache_head, (received_payload->sender_ip.s_addr),
								received_payload->sender_mac,socket_address->sll_ifindex,
								(received_payload->hard_type)); 
			
			//printf("got reply, looking up for %s\n", inet_ntoa(received_payload->sender_ip));
			to_find = (arp_cache_entry*)getARPCacheEntry(arp_cache_head, (received_payload->sender_ip.s_addr));
			if((to_find != NULL))
			{
				//printf("found match for ARP_REPLY in my cache\n");
				if (to_find->domain_sockfd != -1)
				{
					//printf("its not staled out too!!\n");
					to_send_data.ip_addr.sin_addr.s_addr = received_payload->sender_ip.s_addr;
					to_send_data.HWaddr.sll_ifindex = socket_address->sll_ifindex;
					to_send_data.HWaddr.sll_hatype = received_payload->hard_type;
					to_send_data.HWaddr.sll_halen = received_payload->hard_size;
					memcpy(to_send_data.HWaddr.sll_addr, received_payload->sender_mac, ETH_ALEN);
					
					nbytes =  write(to_find->domain_sockfd, (void*)&to_send_data, sizeof(to_send_data));
					if (nbytes < 0)
					{
						perror("On write() back to the api ");
						exit(-1);
					}
					close(to_find->domain_sockfd);
					staleCacheEntrySocket(arp_cache_head, to_find->ip_address.s_addr, to_find->mac_address);
				}
				else
				{
					;//printf("Staled out. This should never happen.\n");
				}
			}
		}
	}
	else
	{
		;//printf("Not my ARP Frame !!\n");
	}
}

int main(int argc, char** argv)
{
	int sockfd, domain_sockfd, length,socket_addr_length, new_sockfd;
	struct sockaddr_un arp_addr;
	fd_set readset;
	struct sockaddr_ll socket_address;
	void* buffer;
	my_ether_hdr *received_hdr;
	arp_message* received_payload;	
	hwaddr* domain_recvd_data;
	struct sockaddr_un domain_sock_addr;
	int domain_sockaddr_length;
	
	buffer = (void*)malloc(ETH_FRAME_LEN);	
	memset(&arp_addr, 0, sizeof(arp_addr));
	
	domain_recvd_data = (void*)malloc(sizeof(hwaddr));
	memset(domain_recvd_data,0, sizeof(hwaddr));
	domain_sockaddr_length = sizeof(domain_sock_addr);

	unlink(ARP_SUN_PATH);

	arp_addr.sun_family = AF_UNIX;
	strcpy(arp_addr.sun_path, ARP_SUN_PATH);
	memset(&socket_address,0,sizeof(struct sockaddr_ll));
	socket_addr_length = sizeof(socket_address);	
	
	build_interface_list();
	sockfd = socket(PF_PACKET, SOCK_RAW, htons(MY_PROTO_ID));
	if (sockfd == -1) 
	{
		perror("On socket() for PF_PACKET ");
		exit(0);
	}	
	if ((domain_sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
	{
		perror("On socket() for Unix socket ");
		exit(0);
	}

	if((bind(domain_sockfd, (struct sockaddr *)&arp_addr, sizeof(arp_addr))) < 0)
	{
		perror("On bind() for Unix socket ");
		exit(0);
	}
	
	listen(domain_sockfd, LISTEN_QUEUE);
	
	for(;;)
	{
		FD_ZERO(&readset);
		FD_SET(domain_sockfd, &readset);
		FD_SET(sockfd, &readset);
		
		if(select(MAX(domain_sockfd, sockfd) + 1, &readset, NULL, NULL, NULL) < 0)
		{
			if(errno == EINTR)
			{
				printf("EINTR: Continuing with normal operation - %s\n", strerror(errno));
				continue;
			}
		}

		if (FD_ISSET(domain_sockfd, &readset)) 
		{
			//printf("Domain socket ready to read data!\n");
			memset(domain_recvd_data, 0, sizeof(hwaddr));
			
			new_sockfd = accept(domain_sockfd,(struct sockaddr*)&domain_sock_addr, &domain_sockaddr_length);
			if(new_sockfd < 0)
			{
				if (errno == EINTR)
					continue;
				else
				{
					perror("On accept() for domain socket ");
					exit(0);
				}
			}
			//printf("calling processDomainSocketData()\n");
			processDomainSocketData(new_sockfd, sockfd);
		}
		if (FD_ISSET(sockfd, &readset)) 
		{
			//printf("PF socket ready to read data!\n");
			memset(buffer, 0, ETH_FRAME_LEN);
			length = recvfrom(sockfd, buffer, ETH_FRAME_LEN, 0, (struct sockaddr*)&socket_address, &socket_addr_length);
			if (length == -1) 
			{
				perror("On recvfrom() for PF_SOCKET ");
				exit(0);
			}
			received_hdr = (my_ether_hdr*)get_ethernet_hdr(buffer);
			received_payload = (arp_message*)get_ethernet_payload(buffer + sizeof(my_ether_hdr));	
			
			//printf("printing after receiving\n");
			//printARPMessage(received_payload);
			//printf("printing over\n");			
			//printf("calling processReceivedEthernetFrame()\n");
			
			processReceivedEthernetFrame(sockfd, received_hdr,received_payload, &socket_address);
		}
	}

	
	free_hwa_info(hwahead);
	unlink(ARP_SUN_PATH);
	exit(0);		
}

