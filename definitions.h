#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>


#define IPPROTO_MY_VALUE	8410
#define MULTICAST_ADDR	 	"225.0.0.185"
#define MULTICAST_PORT		8684
#define MAXTOURHOPS		50
#define MY_IP_IDENTIFIER	151
#define MY_IP_PROTOCOL		245
#define PING_TTL		60

#define BUF_MAX 	512

struct proto
{
	void	 (*fproc)(char *, ssize_t, struct msghdr *, struct timeval *);
	void	 (*fsend)(void);
	void 	 (*finit)(void);
	struct sockaddr  *sasend;	/* sockaddr{} for send, from getaddrinfo */
	struct sockaddr  *sarecv;	/* sockaddr{} for receiving */
	socklen_t	    salen;		/* length of sockaddr{}s */
	int	   	    icmpproto;	/* IPPROTO_xxx value for ICMP */
} *pr;




struct VMInfo
{
	char name[20];
	struct in_addr ip;
	struct VMInfo* next;
};


struct pingIPPacket
{
	struct iphdr header;
	struct icmp *icmpPacket;
};

struct IPPacketPayload
{
	struct in_addr sourceIP;
	struct in_addr mcastIP;
	unsigned short mcastPort;
	struct in_addr vmIP[MAXTOURHOPS];
	unsigned int position;
	unsigned int tourVMCount;
};

struct IPPacket {
       struct iphdr header;
       char payload[BUF_MAX - 20];
};
