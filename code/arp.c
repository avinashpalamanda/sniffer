#include "../header/head.h"

void print_arp_packet(unsigned char* buffer,int data_size,FILE* logfile){
  //struct iphdr *ip = (struct iphdr *)(buffer+sizeof(struct ethhdr));
  struct arphdr *arp=(struct arphdr*)(buffer + sizeof(struct ethhdr));
  struct ethr_arp *etharp=(struct ethr_arp*)(buffer + sizeof(struct ethhdr)+sizeof(struct arphdr));

  //printf("Check\n");
  fprintf(logfile,"-------------------------------------------------------ARP Header--------------------------------------------------\n");
  switch(ntohs(arp->ar_hrd)){
    case ARPHRD_ETHER :
      fprintf(logfile,"|                                   Hardware Address Format : %u -----> Ethernet\n",ntohs(arp->ar_hrd));
    case ARPHRD_IEEE802:
      fprintf(logfile,"|                                   Hardware Address Format : %u -----> IEEE802.11\n",ntohs(arp->ar_hrd));
    case ARPHRD_ATM:
      fprintf(logfile,"|                                   Hardware Address Format : %u -----> ATM\n",ntohs(arp->ar_hrd));
    default:
      fprintf(logfile,"|                                   Hardware Address Format : %u -----> OTHER\n",ntohs(arp->ar_hrd));
  }

  fprintf(logfile,"|                                   Protocol Address Format : %x\n",ntohs(arp->ar_pro));
  fprintf(logfile,"|                                   Hardware Address Length : %d\n",(unsigned char)(arp->ar_hln));
  fprintf(logfile,"|                                   Protocol Address Length : %d\n",(unsigned char)(arp->ar_pln));

  switch(ntohs(arp->ar_op)){
    case ARPOP_REQUEST:
      fprintf(logfile,"|                                   ARP OPCODE              : %u -------->ARP Request\n",ntohs(arp->ar_op));
      break;
    case ARPOP_REPLY:
      fprintf(logfile,"|                                   ARP OPCODE              : %u -------->ARP Reply\n",ntohs(arp->ar_op));
      break;
    case ARPOP_RREQUEST:
      fprintf(logfile,"|                                   ARP OPCODE              : %u -------->RARP Request\n",ntohs(arp->ar_op));
      break;
    case ARPOP_RREPLY:
      fprintf(logfile,"|                                   ARP OPCODE              : %u -------->RARP reply\n",ntohs(arp->ar_op));
      break;
    case ARPOP_InREQUEST:
      fprintf(logfile,"|                                   ARP OPCODE              : %u -------->InARP Request\n",ntohs(arp->ar_op));
      break;
    case ARPOP_InREPLY:
      fprintf(logfile,"|                                   ARP OPCODE              : %u -------->InARP Reply\n",ntohs(arp->ar_op));
      break;
    }

    fprintf(logfile , "|                                   Sender Hardware Address     : %x-%x-%x-%x-%x-%x \n", etharp->ar_sha[0],etharp->ar_sha[1],etharp->ar_sha[2],etharp->ar_sha[3],etharp->ar_sha[4],etharp->ar_sha[5]);
    fprintf(logfile , "|                                   Destination Hardware Address: %x-%x-%x-%x-%x-%x \n", etharp->ar_tha[0],etharp->ar_tha[1],etharp->ar_tha[2],etharp->ar_tha[3],etharp->ar_tha[4],etharp->ar_tha[5]);

    char ip_str[INET_ADDRSTRLEN];
    uint32_t ip = *(uint32_t *)&etharp->ar_sip[0];
    inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));

    fprintf(logfile , "|                                   Source IP Address       : %s\n", ip_str);

    ip = *(uint32_t *)&etharp->ar_tip[0];
    inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));

    fprintf(logfile , "|                                   Destination IP Address  : %s", ip_str);

    //fprintf(logfile , "|-Target Hardware Address     : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", arp->ar_tha[0] , arp->ar_tha[1] , arp->ar_tha[2] , arp->ar_tha[3] , arp->ar_tha[4] , arp->ar_tha[5] );

    fprintf(logfile,"\n");
    fprintf(logfile,"------------------------------------------------------------------------------------------------------------------\n");


    fprintf(logfile,"\n");
    fprintf(logfile,"Ethernet Header\n");
    PrintData(buffer ,+sizeof(struct ethhdr),logfile);

    fprintf(logfile,"ARP Header\n");
    PrintData(buffer+sizeof(struct ethhdr) , sizeof(struct arphdr),logfile);

    fprintf(logfile,"Data\n");
    PrintData(buffer+sizeof(struct arphdr)+sizeof(struct ethhdr) , data_size - sizeof(struct ethhdr) - sizeof(struct arphdr),logfile);

    fprintf(logfile,"\n###########################################################################################################################\n\n");
    fflush(logfile);

}
