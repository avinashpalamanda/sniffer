#include "../header/head.h"

struct protocol_count counter;

FILE *logfile_tcp;
FILE *logfile_udp;
FILE *logfile_icmp;
FILE *logfile_arp;
FILE *logfile_igmp;
FILE *logfile_others;
int sock_fd;
int i,j;

int main(){
  socklen_t saddr_size,data_size;
  struct sockaddr saddr;
  struct in_addr inaddr;

  counter.ip_count_v4=0;counter.ip_count_v6=0;counter.tcp_count=0;counter.udp_count=0;counter.igmp_count=0;counter.arp_count=0;counter.other=0,counter.ethernet_count=0;

  //Opening a File
  logfile_tcp=fopen("../output/logfile_tcp.txt","w");
  logfile_udp=fopen("../output/logfile_udp.txt","w");
  logfile_icmp=fopen("../output/logfile_icmp.txt","w");
  logfile_igmp=fopen("../output/logfile_igmp.txt","w");
  logfile_arp=fopen("../output/logfile_arp.txt","w");
  logfile_others=fopen("../output/logfile_other.txt","w");

  unsigned char *buffer = (unsigned char *)malloc(65536);//Buffer to hold recieved data

  sock_fd=socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));//Creating a new Socket
  if(sock_fd<0){
    perror("Error\n");
    exit(4);
  }

  saddr_size = sizeof saddr;

  while(1){
    data_size = recvfrom(sock_fd , buffer , 65536 , 0 , &saddr , &saddr_size);//Recieveing Data
    if(data_size <0 ){
      perror("Recvfrom error , failed to get packets\n");
      return 1;
    }
    process_packet(buffer,data_size);
    counter.ethernet_count++;
    system("clear");
    printf("###########################################################################################################################\n");
    printf("                                                     Link Layer                                                        \n");
    printf("                                                                    |Ethernet Count : %lld                              \n",counter.ethernet_count);
    printf("                                                     Network Layer                                                    \n");
    printf("                                                                    |IPv4:%lld IPv6:%lld                                  \n",counter.ip_count_v4,counter.ip_count_v6);
    printf("                                                     Transport Layer                                                  \n");
    printf("                                                                    |TCP:%lld UDP:%lld                                    \n",counter.tcp_count,counter.udp_count);
    printf("                                                     Other Protocols                                                  \n");
    printf("                                                                    |ICMP:%lld IGMP:%lld ARP:%lld Other:%lld                  \n",counter.icmp_count,counter.igmp_count,counter.arp_count,counter.other);
    printf("###########################################################################################################################\n");

  }
}
