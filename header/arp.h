#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/ip_icmp.h>//Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<net/if_arp.h>
#include<netinet/if_ether.h>
#include<sys/socket.h>
#include<arpa/inet.h>

struct ethr_arp{
  unsigned char           ar_sha[ETH_ALEN];       /* sender hardware address      */
  unsigned char           ar_sip[4];              /* sender IP address            */
  unsigned char           ar_tha[ETH_ALEN];       /* target hardware address      */
  unsigned char           ar_tip[4];              /* target IP address            */
};

extern void print_arp_packet(unsigned char*,int,FILE*);//Printing ICMP Packet
