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
#include<netinet/igmp.h>

extern void print_igmp_packet(unsigned char*,int,FILE*);//Printing ICMP Packet
extern void print_record_type(FILE*,u_int8_t);

#define IGMPV3_MODE_IS_INCLUDE          1
#define IGMPV3_MODE_IS_EXCLUDE          2
#define IGMPV3_CHANGE_TO_INCLUDE        3
#define IGMPV3_CHANGE_TO_EXCLUDE        4
#define IGMPV3_ALLOW_NEW_SOURCES        5
#define IGMPV3_BLOCK_OLD_SOURCES        6
