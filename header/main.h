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

/*Global variable File access & socket id*/
#define STDIN 0
extern FILE *logfile_tcp;
extern FILE *logfile_udp;
extern FILE *logfile_icmp;
extern FILE *logfile_arp;
extern FILE *logfile_igmp;
extern FILE *logfile_others;
extern int sock_fd;
extern int i,j;

extern struct protocol_count{
  long long int ip_count_v4;
  long long int ip_count_v6;
  long long int tcp_count,udp_count;
  long long int icmp_count,igmp_count,other;
  long long int arp_count;
  long long int ethernet_count;
}counter;

/*Functions*/
extern void process_packet(unsigned char*,int);//Processing a Incoming  Packet
extern void process_ip_packet(unsigned char*,int);//Processing a Incoming IP Packet

extern void PrintData (unsigned char*, int,FILE*);//Printing Data

extern void print_eth_packet(unsigned char*,int,FILE*);
extern void print_ip_packet(unsigned char*,int,FILE*);//Printing IP Packet
extern void print_tcp_packet(unsigned char*,int,FILE*);//Printing TCP Packet
extern void print_icmp_packet(unsigned char*,int,FILE*);//Printing ICMP Packet
