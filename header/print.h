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

extern void PrintData (unsigned char*, int,FILE*);//Printing Data
extern void print_eth_packet(unsigned char*,int,FILE*);
extern void print_ip_packet(unsigned char*,int,FILE*);//Printing IP Packet
extern void print_tcp_packet(unsigned char*,int,FILE*);//Printing TCP Packet
extern void print_udp_packet(unsigned char*,int,FILE*);//Printing TCP Packet
