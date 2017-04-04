#include "../header/head.h"
#include "../header/print_igmp.h"
void process_packet(unsigned char* buffer,int data_size){

  struct ethhdr *eth = (struct ethhdr *)buffer;
  if(eth->h_proto == 8)
    process_ip_packet(buffer,data_size);
  else if(ntohs(eth->h_proto)==806){
    counter.arp_count++;
    printf("ARP\n");
    print_eth_packet(buffer,data_size,logfile_arp);
    print_ip_packet(buffer,data_size,logfile_arp);
    print_arp_packet(buffer,data_size,logfile_arp);
    fflush(logfile_arp);
  }
}

void process_ip_packet(unsigned char* buffer,int data_size){
  struct iphdr *iph=(struct iphdr*)(buffer+sizeof(struct ethhdr));

  /*Counting IPv4 and IPv6*/
  if((unsigned int)iph->version == 4)
    counter.ip_count_v4++;
  else
    counter.ip_count_v6++;

  /*Identifying the Upper Layer Protocol*/
  switch(iph->protocol){
    case 2:                 //IGMP Packet
      counter.igmp_count++;
      print_eth_packet(buffer,data_size,logfile_igmp);
      print_ip_packet(buffer,data_size,logfile_igmp);//Printing IP Packet
      print_igmp_packet(buffer,data_size,logfile_igmp);
      fflush(logfile_igmp);
      break;
    case 1:                 //ICMP Packet
      counter.icmp_count++;
      print_eth_packet(buffer,data_size,logfile_icmp);
      print_ip_packet(buffer,data_size,logfile_icmp);//Printing IP Packet
      print_icmp_packet(buffer,data_size,logfile_icmp);
      fflush(logfile_icmp);
      break;
    case 6:                 //TCP Packet
      counter.tcp_count++;
      print_eth_packet(buffer,data_size,logfile_tcp);
      print_ip_packet(buffer,data_size,logfile_tcp);
      print_tcp_packet(buffer,data_size,logfile_tcp);
      fflush(logfile_tcp);
      break;
    case 17:                //UDP Packet
      counter.udp_count++;
      print_eth_packet(buffer,data_size,logfile_udp);
      print_ip_packet(buffer,data_size,logfile_udp);
      print_udp_packet(buffer,data_size,logfile_udp);
      fflush(logfile_udp);
      break;
    default :
      counter.other++;
      print_eth_packet(buffer,data_size,logfile_others);
      fprintf(logfile_others,"Data Payload\n");
      PrintData(buffer,data_size,logfile_others);
      fprintf(logfile_others,"\n###########################################################################################################################\n\n");

      fflush(logfile_others);
      break;
  }
}
