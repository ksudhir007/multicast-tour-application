#include "my_headers.h"

char * my_sock_ntop_debug(const struct sockaddr *sa, socklen_t salen)
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

char* print_mac_address_debug(unsigned char* mac_addr)
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

int areq(struct sockaddr *IPaddr, socklen_t sockaddrlen, struct hwaddr *HWaddr)
{
	struct sockaddr_un arp_addr;
	int sockfd, nbytes;
	struct timeval timeout;
	fd_set rset;
	api_serialized_data to_send_data, to_recv_data;

	memset(&arp_addr,0, sizeof(struct sockaddr_un));
	memset(&to_send_data, 0, sizeof(api_serialized_data));
	
	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
	{
		perror("On socket() for Unix socket ");
		return -1;
	}	
	
	memcpy(&(to_send_data.ip_addr),IPaddr, sizeof(struct sockaddr_in));
	
	arp_addr.sun_family = AF_UNIX;
	strcpy(arp_addr.sun_path, ARP_SUN_PATH);
	
	//printf("received in areq with %s\n", my_sock_ntop_debug(IPaddr, sockaddrlen));
	
	printf("API: areq() requesting ARP to lookup for IP: %s\n", my_sock_ntop_debug(IPaddr, sockaddrlen));
	if (connect(sockfd, (struct sockaddr*)&arp_addr, sizeof(arp_addr)) != 0)
	{
		perror("On connect() for unix socket ");
		return -1;
	}
	
	nbytes = write(sockfd, (void*)&to_send_data, sizeof(to_send_data));
	
	for(;;)
	{
		timeout.tv_sec = 5;
		timeout.tv_usec = 0;
		FD_ZERO(&rset);
		FD_SET(sockfd, &rset);

		nbytes = select(sockfd + 1, &rset, NULL, NULL, NULL);
		if (nbytes < 0)
		{
			if (errno == EINTR)
				continue;
			else
			{
				perror("On select() in domain socket ");
				return -1;
			}
		}
		
		if (FD_ISSET(sockfd, &rset))
		{
			nbytes = read(sockfd, (void*)&to_recv_data, sizeof(to_recv_data));
			close(sockfd);
			//printf("in api read %d bytes\n", nbytes);
			//printf("socket read areq with %s, interface %d, htype %d, hlen %d, ", inet_ntoa(to_recv_data.ip_addr.sin_addr),
			//       to_recv_data.HWaddr.sll_ifindex, to_recv_data.HWaddr.sll_hatype, to_recv_data.HWaddr.sll_halen);
			//printf("%s-------\n",print_mac_address_debug(to_recv_data.HWaddr.sll_addr));
			memcpy(HWaddr,&(to_recv_data.HWaddr), sizeof(struct hwaddr));
			//printf("copied into out param interface %d, htype %d, hlen %d, ", 
			//       HWaddr->sll_ifindex, HWaddr->sll_hatype, HWaddr->sll_halen);
			//printf("%s-------\n",print_mac_address_debug(HWaddr->sll_addr));	

			printf("API: areq() received from ARP (MAC address: %s; Interface-index: %d; Hardware-type: %d; Hardware-length: %d) for lookup on %s\n", 
					print_mac_address_debug(HWaddr->sll_addr), HWaddr->sll_ifindex, HWaddr->sll_hatype, HWaddr->sll_halen,
				 	my_sock_ntop_debug(IPaddr, sockaddrlen));		
			
			return nbytes;
		}
		if (nbytes == 0)
		{
			printf("Timed out! in areq(), closing connection.\n");
			close(sockfd);
			return -1;
		}
	}
}
