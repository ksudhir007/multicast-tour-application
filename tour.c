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
#include <time.h>


#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdbool.h>


#include "definitions.h"
#include "my_headers.h"


#define ETH_FRAME_SIZE	1518
#define BUFSIZE		1500
#define TTL		1

pid_t pid;

int tourHops=0;

//Can remove
int datalen =56;
char sendbuf[BUFSIZE];
int nsent;
//End

int rt_socket, pg_socket, pf_socket;
int mcast_recv, mcast_send;
int amISource = 0;
int amILast =0;
int countEnd = 0;
int tourEnd = 0;
uint32_t firstTime[MAXTOURHOPS]={0};
int mcastJoin =0;			//To check whether already joined mcast group or not
int indexPing =0;

const char endTourMessage[] = "Tour has ended";

char myName[BUF_MAX];
char my_canonical_ip[BUF_MAX];

struct in_addr myIP, destIP, mcastIP;
struct sockaddr_in destaddr, mcastaddr;
struct hwa_info *eth0;
struct VMInfo* tourHead = NULL;
struct IPPacketPayload IPPayload;



//Some Important Functions

void sig_alrm(int signo)
{
	if(tourEnd != 1)
	{
		(*pr->fsend)();
		alarm(1);
		//return;
	}
	else
	{
		printf("Tour has finished. Will now Exit\n");
		exit(0);
	}
	
	return;
}

// Some utility functions

int myMax(int a, int b)
{
	if(a > b)
		return a;
	else
		return b;
}

char* getVM(struct in_addr vmaddr)
{
	struct hostent *hptr = gethostbyaddr(&vmaddr, sizeof(vmaddr), AF_INET);
	if(hptr == NULL)
	{
		return NULL;
	}
	return strdup((char*)(hptr->h_name));
}

void getMACAddr(unsigned char* haddr)
{
	unsigned char *ptr = haddr;
	int i = IFHWADDRLEN;
	do
	{
		printf("%.2x%s", *ptr++ & 0xff, (i == 1) ? " " : ":");
	} while (--i > 0);
	printf("\n");
}

struct in_addr getIPAddr(char *vm)
{
	struct hostent *hptr;
	hptr = gethostbyname(vm);
	return *(struct in_addr*)(hptr -> h_addr_list[0]);
}

char* printIP(unsigned int s_addr)
{
	struct in_addr addr;
	char* str = calloc(1, INET_ADDRSTRLEN);
	
	addr.s_addr = s_addr;
	
	inet_ntop(AF_INET, (void*)&addr, str, INET_ADDRSTRLEN);
	return str;
}
char* my_sock_ntop(const struct sockaddr *sa, socklen_t salen)
{
    char portstr[8];
    static char str[128];
    struct sockaddr_in *sin;

        switch (sa->sa_family) 
        {
                case AF_INET: 
                {
                        sin = (struct sockaddr_in *) sa;

                        if(inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL)
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


//------------------Multicast related Function------------------------//

void mcastSetup(struct in_addr mcastIPToJoin, unsigned short port)
{
	struct ip_mreq srcMreq;
	//unsigned char ttl;
	int ttl=1;

	memset(&srcMreq, 0, sizeof(struct ip_mreq));

	srcMreq.imr_multiaddr.s_addr = mcastIPToJoin.s_addr;	
	srcMreq.imr_interface.s_addr = myIP.s_addr;

	setsockopt(mcast_recv, IPPROTO_IP, IP_ADD_MEMBERSHIP, &srcMreq, sizeof(struct ip_mreq));
	setsockopt(mcast_send, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));

	printf("Node %s : Joined multicast group with IP address %s:%d.\n", myName, printIP(mcastIPToJoin.s_addr), port);
	
	
}

void mcastSend(char* buffer)
{
	struct sockaddr_in tempMcastAddr;
	memset(&tempMcastAddr, 0, sizeof(struct sockaddr_in));

	tempMcastAddr.sin_family = AF_INET;
	tempMcastAddr.sin_addr.s_addr = mcastIP.s_addr;
	tempMcastAddr.sin_port = (unsigned short) MULTICAST_PORT;
	
	printf("Node %s. Sending : %s\n", myName, buffer);

	if(sendto(mcast_send, buffer, strlen(buffer), 0, (struct sockaddr*)&tempMcastAddr, sizeof(tempMcastAddr)) < 0)
	{
		perror("Multicast sendto failed: Now will exit:");
		exit(1);
	}
 
}

//------------------Multicast related Functions End ------------------------//


//Ping Related Functions
uint16_t in_cksum(uint16_t *addr, int len)
{
       int                                nleft = len;
       uint32_t                sum = 0;
       uint16_t                *w = addr;
       uint16_t                answer = 0;

       /*
        * Our algorithm is simple, using a 32 bit accumulator (sum), we add
        * sequential 16 bit words to it, and at the end, fold back all the
        * carry bits from the top 16 bits into the lower 16 bits.
        */
       while (nleft > 1)  {
               sum += *w++;
               nleft -= 2;
       }

               /* 4mop up an odd byte, if necessary */
       if (nleft == 1) {
               *(unsigned char *)(&answer) = *(unsigned char *)w ;
               sum += answer;
       }

               /* 4add back carry outs from top 16 bits to low 16 bits */
       sum = (sum >> 16) + (sum & 0xffff);        /* add hi 16 to low 16 */
       sum += (sum >> 16);                        /* add carry */
       answer = ~sum;                                /* truncate to 16 bits */
       return(answer);
}

void tv_sub(struct timeval *out, struct timeval *in){
	if ( (out->tv_usec -= in->tv_usec) < 0) {	/* out -= in */
		--out->tv_sec;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
}

void proc_v4(char *ptr, ssize_t len, struct msghdr *msg, struct timeval *tvrecv)
{
	int		hlen1, icmplen;
	double		rtt;
	struct ip	*ip;
	struct icmp	*icmp;
	struct timeval	*tvsend;
	struct sockaddr_in *sin;
	struct in_addr forVMName;
	char msgEnd[BUF_MAX];

	memset(&forVMName, 0, sizeof(struct in_addr));
	ip = (struct ip *) ptr;		/* start of IP header */
	hlen1 = ip->ip_hl << 2;		/* length of IP header */
	if (ip->ip_p != IPPROTO_ICMP)
		return;				/* not ICMP */

	icmp = (struct icmp *) (ptr + hlen1);	/* start of ICMP header */
	if ( (icmplen = len - hlen1) < 8)
		return;				/* malformed packet */

	if (icmp->icmp_type == ICMP_ECHOREPLY) {
		if (icmp->icmp_id != pid)
			return;			/* not a response to our ECHO_REQUEST */
		if (icmplen < 16)
			return;			/* not enough data to use */

		tvsend = (struct timeval *) icmp->icmp_data;
		tv_sub(tvrecv, tvsend);
		rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

		sin = (struct sockaddr_in*) pr->sarecv;
		//forVMName = &sin->sin_addr;		

		printf("<< PING RESPONSE >> %d bytes received from %s %s: seq=%u, ttl=%d, rtt=%.3f ms\n\n",
				icmplen,getVM(sin->sin_addr),my_sock_ntop(pr->sarecv, pr->salen),
				icmp->icmp_seq, ip->ip_ttl, rtt);


		if(amILast == 1)
		{
			countEnd++;
			//printf("$$$$$$$$$$$$$$$$$$$Count value = %d$$$$$$$$$$$$$$$$$$$$$$$$$$\n", countEnd);
			if(countEnd >= 6)
			{
				snprintf(msgEnd, BUF_MAX, "<<<<< This is node %s. Tour has ended. Group members please identify yourselves.>>>>>\n", myName);
				
				mcastSend(msgEnd);
			}
			
		}
	}
}


void send_v4(void)
{
	int			len;
	struct icmp	*icmp;
	struct iphdr* ip;
	int n;
	

	unsigned char srcMac[6];
	unsigned char dstMac[6];

	hwaddr destHwAddr;

	void* buffer = (void*)calloc(1,ETH_FRAME_LEN);
	struct ethhdr *ethHeader = (struct ethhdr *)buffer;
	


	struct pingIPPacket pingPacket;

	struct sockaddr_ll pingLinkLevel;
	memset(&pingLinkLevel, 0, sizeof(struct sockaddr_ll));
	

	

	memset(&destHwAddr, 0, sizeof(destHwAddr));
	memset(&pingPacket, 0, sizeof(struct pingIPPacket));	
	
	if(areq((struct sockaddr*)&destaddr, sizeof(destaddr), &destHwAddr) < 0)
	{
		printf("AREQ Error............Will Noww Exit\n");
		exit(1);
	}

	//packet = malloc(sizeof(struct iphdr) + sizeof(struct icmphdr));
	//memset(packet,0, sizeof(struct iphdr) + sizeof(struct icmphdr));

	//getMACAddr(destHwAddr.sll_addr);

	//00:50:56:00:80:02
	/*destHwAddr.sll_addr[0] =0x00;
	destHwAddr.sll_addr[1] =0x50;
	destHwAddr.sll_addr[2] =0x56;
	destHwAddr.sll_addr[3] =0x00;
	destHwAddr.sll_addr[4] =0x80;
	destHwAddr.sll_addr[5] =0x02;
	destHwAddr.sll_addr[6] =0x00;
	destHwAddr.sll_addr[7] =0x00;	
*/





	icmp = (struct icmp *) sendbuf;
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_hun.ih_idseq.icd_id = pid;
	icmp->icmp_hun.ih_idseq.icd_seq = nsent++;
	memset(icmp->icmp_data, 0xa5, datalen);	
	gettimeofday((struct timeval *) icmp->icmp_data, NULL);

	//len = 8 + datalen;
	len = datalen;		
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = in_cksum((u_short *) icmp, len);

	
	pingPacket.header.version = 4;
	pingPacket.header.ihl = 5;
	pingPacket.header.tos = 0;
	pingPacket.header.tot_len = htons(sizeof(struct iphdr) + len);
	pingPacket.header.id = htons(MY_IP_IDENTIFIER);
	pingPacket.header.frag_off = 0;
	pingPacket.header.ttl = PING_TTL;
	pingPacket.header.protocol = IPPROTO_ICMP;
	pingPacket.header.check = 0;

	pingPacket.header.saddr = myIP.s_addr;
	pingPacket.header.daddr = destaddr.sin_addr.s_addr;
	pingPacket.header.check = in_cksum((u_short *)&(pingPacket.header), sizeof(struct iphdr));


	pingPacket.icmpPacket = (struct icmp*)calloc(1,len);
	memcpy((void*)pingPacket.icmpPacket, (void*)icmp, len);

	
	memcpy((void*)srcMac, (void*)eth0->if_haddr, ETH_ALEN);
	memcpy((void*)dstMac, (void*)destHwAddr.sll_addr, ETH_ALEN);

	pingLinkLevel.sll_family   = PF_PACKET;
	pingLinkLevel.sll_protocol = htons(ETH_P_IP);
	pingLinkLevel.sll_ifindex  = eth0->if_index;
	pingLinkLevel.sll_hatype   = ARPHRD_ETHER;
	pingLinkLevel.sll_pkttype  = PACKET_OTHERHOST;
	pingLinkLevel.sll_halen    = ETH_ALEN;

	/*MAC - start*/
	memcpy((void*)pingLinkLevel.sll_addr, (void*)destHwAddr.sll_addr, ETH_ALEN);
	/*MAC - end*/
	pingLinkLevel.sll_addr[6]  = 0x00;/*not used*/
	pingLinkLevel.sll_addr[7]  = 0x00;/*not used*/

	memcpy((void*)buffer, (void*)dstMac, ETH_ALEN);
	memcpy((void*)(buffer+ETH_ALEN), (void*)srcMac,ETH_ALEN);
	ethHeader->h_proto = htons(ETH_P_IP);
	memcpy((void*)(buffer+14), (void*)&pingPacket, sizeof(struct iphdr));
	memcpy((void*)(buffer+14+(sizeof(struct iphdr))), (void*)pingPacket.icmpPacket ,len );
	
	printf("Sending a ping pcket\n");

	n = sendto(pf_socket, buffer, ETH_FRAME_LEN, 0, (struct sockaddr*)&pingLinkLevel, sizeof(pingLinkLevel));
	
	if(n < 0)
	{
		perror("Sendto while sending ping echo request failed:");
		exit(1);
	}

	printf("PINGING %s : %d bytes of data\n", getVM(destaddr.sin_addr), n);

	sendto(pg_socket, sendbuf, len, 0, pr->sasend, pr->salen);
}

int checkFirstTime(uint32_t value)
{
	int i=0;
	if(indexPing == 0)
	{
		firstTime[indexPing++] = value;
		return 1;
	}
	for(i=0; i< indexPing; i++)
	{
		if(firstTime[i] == value)
		{
			return 0;
		}
	}
	firstTime[indexPing++] = value;
	return 1;
	
	
}

void ping_v4(char* vmToPing)
{
	struct hostent *hptr;
	struct in_addr ipOfVM;

	memset(&destaddr, 0, sizeof(struct sockaddr_in));
	hptr = gethostbyname(vmToPing);
	ipOfVM = getIPAddr(vmToPing);

	if(checkFirstTime(ipOfVM.s_addr) == 0)
	{
		printf("Already in the list. Will not ping again\n");
		return;
	}	
	
	printf("Pinging : %s\n", vmToPing);
	
	destaddr.sin_family = AF_INET;
	destaddr.sin_addr = *(struct in_addr*)(hptr->h_addr_list[0]); 

	printf("IP address of destination = %s\n", inet_ntoa(destaddr.sin_addr));
	
	sig_alrm(SIGALRM);
	
}

//End of Ping related Functions


struct proto proto_v4 = { 
				proc_v4, 
				send_v4, 
				NULL, 
				NULL, 
				NULL, 
				0, 
				IPPROTO_ICMP 
			};


//--------------------Tour Related Functions -----------------------------//

void printTour(struct VMInfo* node)
{
	
	struct VMInfo* temp = node;	

	if(node == NULL)
        {
                printf("No tour associated \n");
                return;
        }

	
	while(temp->next != NULL)
	{
		printf("%s : %s ", temp->name, printIP((temp->ip).s_addr));
		temp = temp->next;
	}
	printf("%s : %s \n", temp->name,printIP((temp->ip).s_addr));
}

void insertIntoList(struct VMInfo* node)
{
	struct VMInfo* temp = tourHead;
	if(temp == NULL) 
	{
		tourHead=node;
	}
	else
	{
		while(temp->next != NULL)
		{
			temp = temp->next;
		}
		temp->next = node;
	}
	return;
}

void initialProcessing(int argc, char** argv)
{
	struct hostent *hptr;
	struct VMInfo *vm;
	struct in_addr prevVM;
	int i=0;	

	if(argc < 2)
	{
		printf("Not the source node which started the tour\n");
		return;
	}

	amISource = 1;
	tourHops = argc-1;

	for(i=1; i<=tourHops; i++)
	{
		if((hptr = gethostbyname(argv[i]))!=NULL)
	        {
        		vm = calloc(1, sizeof(struct VMInfo));
			vm->ip = *(struct in_addr*)(hptr->h_addr_list[0]);
			if(i != 1 && (vm->ip.s_addr == prevVM.s_addr))
			{
				printf("Invalid Tour : Two same Consecutive VM's: The program will exit now.\n");
				exit(0);
			}
			strcpy(vm->name, argv[i]);
			prevVM.s_addr = vm->ip.s_addr;
			vm->next = NULL;

			insertIntoList(vm);		
		
        	}	
        	else
        	{
                	perror("Error: gethostbyname(): Invalid VM in arguement:");
                	exit(1);
        	}

		
	}

	printTour(tourHead);
	
}

void build_interface_list()
{
	struct hwa_info *hwa, *hwahead;
	struct sockaddr	*sa;
	struct sockaddr_in *sin;
	
	hwa = hwahead = Get_hw_addrs();
	
	
	while(hwa != NULL)
	{
		if ((strcmp(hwa->if_name, "eth0") == 0))
		{
			if ((sa = hwa->ip_addr) != NULL)
			{
				
				memset(&myIP, 0, sizeof(struct in_addr));
				sprintf(my_canonical_ip, "%s", (char *)my_sock_ntop(sa, sizeof(*sa)));
				sin = (struct sockaddr_in*)sa;
				
				myIP = sin->sin_addr;
				
			}
			eth0 = hwa;
			
		}
		
		hwa = hwa->hwa_next;
	}
}


void sendRTPacket(struct IPPacketPayload* ipPayload)
{

	struct IPPacket* sendIPPacket;
	struct sockaddr_in destaddrRT;
	struct iphdr* ipHeader;
	int n;
	
	memset(&destaddrRT, 0, sizeof(struct sockaddr_in));
	
	destaddrRT.sin_addr = ipPayload->vmIP[ipPayload->position++];
	destaddrRT.sin_family = AF_INET;
	
	
	printf("Index of vmIP list = %d\n", ipPayload->position);

	

	sendIPPacket = calloc(1, sizeof(struct IPPacket));
	
	ipHeader = &(sendIPPacket->header);
	
	ipHeader->version = 4;
	ipHeader->ihl = 5;
	ipHeader->tos = 0;
	ipHeader->tot_len = htons(sizeof(struct IPPacket));
	ipHeader->id = htons(MY_IP_IDENTIFIER);
	ipHeader->frag_off = 0;	
	ipHeader->ttl = PING_TTL;
	ipHeader->protocol = MY_IP_PROTOCOL;
	ipHeader->check = 0;
	ipHeader->check = in_cksum((u_short *)ipHeader, sizeof(struct iphdr));
		
	ipHeader->saddr = myIP.s_addr;
	ipHeader->daddr = destaddrRT.sin_addr.s_addr;
	

	memcpy(sendIPPacket->payload, ipPayload, sizeof(struct IPPacketPayload));
	
		

	n = sendto(rt_socket, sendIPPacket, sizeof(struct IPPacket), 0, (struct sockaddr*)&destaddrRT, sizeof(destaddrRT));
	
	if(n < 0)
	{
		perror("Sendto while sending rtPacket failed:");
		exit(1);
	}

	printf("*********Sending Tour packet to %s of %d bytes ***********\n", getVM(destaddrRT.sin_addr), n);

}




//Handlers for sockets

void pingResponseProcessing(void)
{
	char recvbuf[BUFSIZE];
	char controlbuf[BUFSIZE];
	struct msghdr	msg;
	struct iovec	iov;
	ssize_t	n;
	struct timeval	tval;
	char msgEnd[BUF_MAX];
	
	//printf("In receive\n");
	memset(msgEnd, 0, BUF_MAX);

	iov.iov_base = recvbuf;
	iov.iov_len = sizeof(recvbuf);
	msg.msg_name = pr->sarecv;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = controlbuf;

	
	for ( ; ; )
	{
		msg.msg_namelen = pr->salen;
		msg.msg_controllen = sizeof(controlbuf);
		n = recvmsg(pg_socket, &msg, 0);
		if (n < 0) 
		{
			if (errno == EINTR)
				continue;
			else
			{
				perror("recvmsg error in pg_socket");
				exit(1);
			}
		}

		if(gettimeofday(&tval, NULL) < 0)
		{
			perror("gettimeofday error in pg_socket:");
			exit(1);
		}
		(*pr->fproc)(recvbuf, n, &msg, &tval);

		
		break;

	}
}

void mcastSocketHandler(void)
{
	struct sockaddr_in tempMcastAddr;
	char recvBuffer[BUF_MAX];
	socklen_t tempLength = sizeof(struct sockaddr_in);

	memset(recvBuffer, 0, BUF_MAX);
	memset(&tempMcastAddr, 0, sizeof(struct sockaddr_in));

	if((recvfrom(mcast_recv, recvBuffer, BUF_MAX, 0, (struct sockaddr*)&tempMcastAddr, &tempLength)) < 0)
	{
		perror("Multicast recvfrom error: Will Now exit:");
		return;
	}
	
	printf("Node %s: Received : %s \n", myName, recvBuffer);
	
	if(strstr(recvBuffer, endTourMessage) != NULL)
	{
		tourEnd = 1;
		memset(recvBuffer, 0, BUF_MAX);
		snprintf(recvBuffer, BUF_MAX, "<<<<< Node %s .  I am a member of the group. >>>>>", myName);
		mcastSend(recvBuffer);
		
	}
	else if(strstr(recvBuffer, "I am a member of the group") != NULL)
		{
			//printf("Will Wait for 5 secs before exiting\n");
			if(tourEnd == 1)
			{
				alarm(1);
			}
			
		}
	
	return;
}


void rtSocketHandler(void)
{
	struct IPPacket *recvPacket;
	struct IPPacketPayload recvPayload;
	struct sockaddr_ll recvAddr;
	struct in_addr recvSrc, recvDest;
	
	char *srcVM, *destVM;
	char *message;
	time_t ticks;
	int n;
	char timeBuf[BUF_MAX];
	char tempBuffer[BUF_MAX];
	socklen_t recvAddrlen;

	recvPacket = calloc(1, sizeof(struct IPPacket));
	memset(&recvPayload, 0, sizeof(struct IPPacketPayload));
	memset(&recvAddr, 0, sizeof(struct sockaddr_ll));
	memset(timeBuf, 0, BUF_MAX);

	recvAddrlen = sizeof(struct sockaddr_ll);

	n = recvfrom(rt_socket, (void*)recvPacket, sizeof(struct IPPacket), 0, (struct sockaddr*)&recvAddr, &recvAddrlen);
	if(n < 0)
	{
		perror("Error: recvfrom in rt_socket failed :");
		exit(1);
	}

	memset(&recvSrc, 0, sizeof(struct in_addr));
	memset(&recvDest, 0, sizeof(struct in_addr));

	if(ntohs(recvPacket->header.id) == MY_IP_IDENTIFIER && (recvPacket->header.protocol == MY_IP_PROTOCOL))
	{
		recvSrc.s_addr = recvPacket->header.saddr;
		recvDest.s_addr = recvPacket->header.daddr;
		srcVM = getVM(recvSrc);
		destVM = getVM(recvDest);

	
		ticks = time(NULL);
		snprintf(timeBuf, sizeof(timeBuf), "%.24s",ctime(&ticks));
		printf("%s : received source routing packet from %s\n", timeBuf, srcVM);

		memcpy(&recvPayload, recvPacket->payload, sizeof(struct IPPacketPayload));
		
		if(mcastJoin == 0)
		{
			mcastJoin = 1;
			mcastIP = recvPayload.mcastIP;
			mcastSetup(recvPayload.mcastIP, recvPayload.mcastPort);
			message = calloc(1, BUF_MAX);
			snprintf(message, BUF_MAX, "Node %s: Sending : Just joined multicast group\n",destVM);
		
			mcastSend(message);
			
		}
		else
		{
			printf("Already in a mcast Group\n");
		}
		
		// Forwarding the IP packet
		if(recvPayload.position == (recvPayload.tourVMCount))
		{
			// Last node reached
			amILast = 1;
			//snprintf(tempBuffer, BUF_MAX, "Tour has ended.");
	//mcastSend(tempBuffer);
			
			
		}
		else
		{
			sendRTPacket(&recvPayload);
		}
		
		ping_v4(srcVM);

	}

	
}


int main(int argc, char **argv)
{
	struct hwa_info *eth0Info;
	struct hostent *hptr;
	
	int size = 60*1024;
	int on = 1;
	int i=0;	
	int n; 			//For select call output

	

	struct sockaddr temp;
	struct hwa_info *myEth0;
	struct VMInfo* tempList;
	
	char tempBuffer[BUF_MAX];


	struct sockaddr_in servaddr;
	struct sockaddr_in *tempAddr;

	fd_set rset;
	int maxfdp1;


	pid = getpid() & 0xffff;

	memset(&temp, 0, sizeof(struct sockaddr));
	memset(myName, 0, BUF_MAX);	
	memset(&myIP, 0, sizeof(struct in_addr));
	memset(my_canonical_ip, 0, BUF_MAX);
	memset(&IPPayload, 0, sizeof(struct IPPacketPayload));
	memset(tempBuffer, 0, BUF_MAX);

	//Initializing the struct proto
	pr = &proto_v4;
	pr->sarecv = &temp;
	pr->salen = sizeof(struct sockaddr);
	

	gethostname(myName, BUF_MAX);
	
	printf("Name of the machine is : %s \n",myName);
	
	initialProcessing(argc, argv);
	
	signal(SIGALRM, sig_alrm);


	if((hptr = gethostbyname(myName))!=NULL)
	{
		myIP = *(struct in_addr*)(hptr->h_addr_list[0]);

		//printf("IP address : %s\n", inet_ntoa(myIP));

		build_interface_list();		
		myEth0 = eth0;
		
		//tempAddr = (struct sockaddr_in*)&(myEth0->ip_addr);
		//myIP = (tempAddr->sin_addr);
		//printf("IP address of eth0 with my code: %s\n", inet_ntoa(myIP));
		printf("IP address of eth0 = %s\n", my_canonical_ip);
		
		
	}
	else
	{
		perror("Error: gethostbyname() :");
		return(EXIT_FAILURE);
	}
		

	//
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr = myIP;
	
	pr->sasend = (struct sockaddr*)&servaddr;

	//

	// Creating rt Socket
	rt_socket = socket(AF_INET, SOCK_RAW, MY_IP_PROTOCOL);
	if(rt_socket<0)
	{
		perror("RT_Socket creation failed\n");
		exit(1);
		
	}	
	setsockopt(rt_socket, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) ;
	
	
	//Creating pg Socket
	pg_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(pg_socket<0)
	{
		perror("PG_Socket creation failed\n");
		exit(1);
		
	}	
	setsockopt(pg_socket, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
	

	// Create PF socket
	pf_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if(pf_socket<0)
	{
		perror("PF_Socket creation failed\n");
		exit(1);
		
	}


	//Multicasting code starts here
	if(inet_aton((const char*)MULTICAST_ADDR, &mcastIP) < 0)
	{
		perror("inet_aton error:");
		exit(1);
	}
	//printf("Mcast address : %u\n", mcastIP.s_addr);
	
	mcastaddr.sin_addr.s_addr = mcastIP.s_addr;
	mcastaddr.sin_port = (unsigned short) MULTICAST_PORT;
	mcastaddr.sin_family = AF_INET;
	
	mcast_recv = socket(AF_INET, SOCK_DGRAM, 0);
	if(mcast_recv < 0)
	{
		perror("Creation of UDP socket for mcast_recv failed\n");
		exit(1);
	}
	
	mcast_send = socket(AF_INET, SOCK_DGRAM, 0);
	if(mcast_send < 0)
	{
		perror("Creation of UDP socket for mcast_send failed\n");
		exit(1);
	}	

	on  = 1;
	setsockopt(mcast_recv, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
	if(bind(mcast_recv, (struct sockaddr *) &mcastaddr, sizeof(mcastaddr)) < 0)
	{
		perror("Bind error:");
		exit(1);
	}

	


	//If I am source, I'll create an IP packet and send it onto rt_socket
	//And also will create a multicast group, which will be joined by others
	
	if(amISource == 1)
	{
		IPPayload.sourceIP  = getIPAddr(myName);
		//IPPacket.sourceIP  = myIP;
		IPPayload.mcastIP = mcastIP;
		IPPayload.mcastPort = (unsigned short) MULTICAST_PORT;
		IPPayload.position = 0;
		IPPayload.tourVMCount = tourHops;
		tempList = tourHead;
		for(i=0; i<tourHops; i++)
		{
			IPPayload.vmIP[i] = tempList->ip;
			tempList = tempList->next;
		}

		
		mcastSetup(IPPayload.mcastIP, IPPayload.mcastPort);	
	
		mcastJoin = 1;		
		
	  	sendRTPacket(&IPPayload);

	}
	

	
	

	printf("...................Waiting for connections................\n");

	//snprintf(tempBuffer, BUF_MAX, "Tour has ended.");
	//mcastSend(tempBuffer);
	//ping_v4("vm2");

	//sig_alrm(SIGALRM);
	while(1)
	{
		FD_ZERO(&rset);
		FD_SET(pg_socket, &rset);
		FD_SET(mcast_recv, &rset);
		FD_SET(rt_socket,&rset);
		maxfdp1 = myMax(pg_socket, mcast_recv)+1;
		maxfdp1 = myMax(rt_socket, (maxfdp1-1))+1;
		
		

		n = select(maxfdp1, &rset, NULL, NULL, NULL);
		if(n < 0 && (errno==EINTR))
		{
			continue;
		}
		else if(n < 0){
			perror("Error in select Call :");
			exit(1);
		}

		if(FD_ISSET(pg_socket, &rset)){
			//printf("Here I'll process Ping Response Packet\n");
			pingResponseProcessing();
		}

		if(FD_ISSET(rt_socket, &rset)){
			//printf("Inside rt socket\n");
			rtSocketHandler();
		}
		if(FD_ISSET(mcast_recv, &rset)){
			//printf("Multicast Message Received\n");
			mcastSocketHandler();
		}
	}
	return 0;

}
