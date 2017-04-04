#include "../header/head.h"

void print_icmp_packet(unsigned char* buffer,int data_size,FILE* logfile){
  struct iphdr *ip = (struct iphdr *)(buffer+sizeof(struct ethhdr));
  struct icmphdr *icmp=(struct icmphdr*)(buffer + (ip->ihl*4)+sizeof(struct ethhdr));

  fprintf(logfile,"-------------------------------------------------------ICMP Header--------------------------------------------------\n");

  switch((unsigned int)(icmp->type)){
    case ICMP_ECHOREPLY:
      fprintf(logfile,"|                                   ICMP Type               : %d --------------------> ECHO REPLY\n",(unsigned int)(icmp->type));
      break;

    case ICMP_DEST_UNREACH:
      fprintf(logfile,"|                                   ICMP Type               : %d --------------------> ICMP_DEST_UNREACH\n",(unsigned int)(icmp->type));
      switch((unsigned int)(icmp->type)){
        case ICMP_NET_UNREACH:
          fprintf(logfile,"|                                   ICMP Code               : %d --------------------> Network Unreachable\n",(unsigned int)(icmp->code));
        case ICMP_HOST_UNREACH:
          fprintf(logfile,"|                                   ICMP Code               : %d --------------------> Host Unreachable\n",(unsigned int)(icmp->code));
        case ICMP_PROT_UNREACH:
          fprintf(logfile,"|                                   ICMP Code               : %d --------------------> Protocol Unreachable\n",(unsigned int)(icmp->code));
        case ICMP_PORT_UNREACH:
          fprintf(logfile,"|                                   ICMP Code               : %d --------------------> Port Unreachable\n",(unsigned int)(icmp->code));
      }
      break;

    case ICMP_ECHO:
      fprintf(logfile,"|                                   ICMP Type                : %d --------------------> ECHO REQUEST\n",(unsigned int)(icmp->type));
      break;

    case ICMP_TIME_EXCEEDED:
      switch((unsigned int)(icmp->code)){
        case ICMP_EXC_TTL:
          fprintf(logfile,"|                                   ICMP Code                : %d --------------------> TTL count exceeded\n",(unsigned int)(icmp->code));
      }
      break;
    default:
        fprintf(logfile,"|                                   ICMP Type               : %d --------------------> Unknown\n",(icmp->type));
        fprintf(logfile,"|                                   ICMP Code               : %d --------------------> Unknown\n",(icmp->code));
        break;
    }
    fprintf(logfile,"------------------------------------------------------------------------------------------------------------------\n");
    /*fprintf(logfile,"|ICMP Type            : %x \n",(icmp->type));
    fprintf(logfile,"|ICMP Code            : %x \n",(icmp->code));
    fprintf(logfile,"|ICMP Checksum        : %d \n",(unsigned int)(icmp->checksum));
*/

      fprintf(logfile,"\n");
      fprintf(logfile,"Ethernet Header\n");
      PrintData(buffer ,+sizeof(struct ethhdr),logfile);

      fprintf(logfile,"IP Header\n");
      PrintData(buffer+sizeof(struct ethhdr) , (ip->ihl*4),logfile);

      fprintf(logfile,"ICMP Header\n");
      PrintData(buffer+(ip->ihl*4)+sizeof(struct ethhdr) , sizeof icmp,logfile);

      fprintf(logfile,"Data Payload\n");
      PrintData(buffer+(ip->ihl*4)+sizeof icmp ,( data_size - sizeof(struct ethhdr) - sizeof icmp - ip->ihl * 4 ),logfile);

      fprintf(logfile,"\n###########################################################################################################################\n\n");

      fflush(logfile);

}
