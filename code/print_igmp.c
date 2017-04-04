#include "../header/head.h"


void print_igmp_packet(unsigned char* buffer,int data_size,FILE* logfile) { //printf("check\n");
  struct iphdr *ip = (struct iphdr *)(buffer+sizeof(struct ethhdr));
  struct igmp *igmp_type=(struct igmp*)(buffer + (ip->ihl*4)+sizeof(struct ethhdr));

  //PrintData(buffer+(ip->ihl*4)+sizeof(struct ethhdr) , sizeof igmp,logfile);
  int igmp_msg_type=igmp_type->igmp_type;

  fprintf(logfile,"-------------------------------------------------------IGMP Header--------------------------------------------------\n");
  switch(igmp_msg_type){
    case IGMP_MEMBERSHIP_QUERY:
      fprintf(logfile,"|                                   IGMP Type              : Membership Query(%.2X)\n",(igmp_msg_type));
      fprintf(logfile,"|                                   IGMP Time              : %.2X\n",buffer[(ip->ihl*4)+sizeof(struct ethhdr)+1]);
      fprintf(logfile,"|                                   IGMP Csum              : %.2X%.2X\n",buffer[(ip->ihl*4)+sizeof(struct ethhdr)+2],buffer[(ip->ihl*4)+sizeof(struct ethhdr)+3]);
      fprintf(logfile,"|                                   Address                : %d.%d.%d.%d\n",buffer[(ip->ihl*4)+sizeof(struct ethhdr)+4],buffer[(ip->ihl*4)+sizeof(struct ethhdr)+5],buffer[(ip->ihl*4)+sizeof(struct ethhdr)+6],buffer[(ip->ihl*4)+sizeof(struct ethhdr)+7]);
      break;

    case IGMP_V1_MEMBERSHIP_REPORT:
      fprintf(logfile,"|                                   IGMP Type              : Ver. 1 Membership Report(%.2X)\n",(igmp_msg_type));
      break;
    case IGMP_V2_MEMBERSHIP_REPORT:
      fprintf(logfile,"|                                   IGMP Type              : Ver. 2 Membership Report(%.2X)\n",(igmp_msg_type));
      fprintf(logfile,"|                                   IGMP Code              : %.2X \n",(igmp_type->igmp_code));
      fprintf(logfile,"|                                   IGMP Checksum          : %.2X \n",(igmp_type->igmp_cksum));
      fprintf(logfile,"|                                   Source Address         : %s\n",inet_ntoa((igmp_type->igmp_group)));
      break;

    case 0x22:
      fprintf(logfile,"|                                   IGMP Type              : Ver. 3 Membership Report(%.2X)\n",(igmp_msg_type));
      fprintf(logfile,"|                                   IGMP Reserved          : %.2X\n",buffer[(ip->ihl*4)+sizeof(struct ethhdr)+1]);
      fprintf(logfile,"|                                   IGMP Checksum          : %.2X%.2X\n",buffer[(ip->ihl*4)+sizeof(struct ethhdr)+2],buffer[(ip->ihl*4)+sizeof(struct ethhdr)+3]);
      fprintf(logfile,"|                                   IGMP Reserved          : %.2X%.2X\n",buffer[(ip->ihl*4)+sizeof(struct ethhdr)+4],buffer[(ip->ihl*4)+sizeof(struct ethhdr)+5]);
      fprintf(logfile,"|                                   IGMP Number of grp     : %.2X%.2X\n",buffer[(ip->ihl*4)+sizeof(struct ethhdr)+6],buffer[(ip->ihl*4)+sizeof(struct ethhdr)+7]);

      u_int8_t x=(int)buffer[(ip->ihl*4)+sizeof(struct ethhdr)+8];
      print_record_type(logfile,x);

      fprintf(logfile,"|                                   IGMP Record Type       : %.2X\n",x);
      fprintf(logfile,"|                                   IGMP AUX data len      : %d\n",buffer[(ip->ihl*4)+sizeof(struct ethhdr)+9]);
      fprintf(logfile,"|                                   IGMP Num src           : %d%.d\n",buffer[(ip->ihl*4)+sizeof(struct ethhdr)+10],buffer[(ip->ihl*4)+sizeof(struct ethhdr)+11]);
      fprintf(logfile,"|                                   Address                : %d.%d.%d.%d\n",buffer[(ip->ihl*4)+sizeof(struct ethhdr)+12],buffer[(ip->ihl*4)+sizeof(struct ethhdr)+13],buffer[(ip->ihl*4)+sizeof(struct ethhdr)+14],buffer[(ip->ihl*4)+sizeof(struct ethhdr)+15]);

      break;

    case IGMP_V2_LEAVE_GROUP:
      fprintf(logfile,"|                                   IGMP Type              : Leave-Group Message (%.2X)\n",(igmp_msg_type));
      break;

    case IGMP_DVMRP:
      fprintf(logfile,"|                                   IGMP Type              : DVMRP Routing Message (%.2X)\n",(igmp_msg_type));
      break;
    case IGMP_PIM:
      fprintf(logfile,"|                                   IGMP Type              : PIM routing message(%.2X)\n",(igmp_msg_type));
      break;

    case IGMP_MTRACE_RESP :
      fprintf(logfile,"|                                   IGMP Type              : Traceroute Resp.(to sender)(%.2X)\n",(igmp_msg_type));
      break;
    case IGMP_MTRACE:
      fprintf(logfile,"|                                   IGMP Type              : Mcast Traceroute Messages(%.2X)\n",(igmp_msg_type));
      break;

    case IGMP_MAX_HOST_REPORT_DELAY:
      fprintf(logfile,"|                                   IGMP Type              : MAX Delay for Response to Query(%.2X)\n",(igmp_msg_type));
      break;
  }
  fprintf(logfile,"------------------------------------------------------------------------------------------------------------------\n");

  fprintf(logfile,"Ethernet Header\n");
  PrintData(buffer ,+sizeof(struct ethhdr),logfile);

  fprintf(logfile,"IP Header\n");
  PrintData(buffer+sizeof(struct ethhdr) ,(ip->ihl*4),logfile);

  fprintf(logfile,"IGMP Header\n");
  PrintData(buffer+sizeof(struct ethhdr)+(ip->ihl*4) ,data_size-(ip->ihl*4)-sizeof(struct ethhdr),logfile);

  fprintf(logfile,"\n###########################################################################################################################\n\n");

  fflush(logfile);


}

void print_record_type(FILE* logfile,u_int8_t type){
  switch(type){
    case IGMPV3_MODE_IS_INCLUDE:
      fprintf(logfile,"|                                   IGMP Record Type       : IGMPV3_MODE_IS_INCLUDE(%.2X)\n",type);
      break;
    case IGMPV3_MODE_IS_EXCLUDE:
      fprintf(logfile,"|                                   IGMP Record Type       : IGMPV3_MODE_IS_EXCLUDE(%.2X)\n",type);
      break;
    case IGMPV3_CHANGE_TO_INCLUDE:
      fprintf(logfile,"|                                   IGMP Record Type       : IGMPV3_CHANGE_TO_INCLUDE(%.2X)\n",type);
      break;
    case IGMPV3_CHANGE_TO_EXCLUDE:
      fprintf(logfile,"|                                   IGMP Record Type       : IGMPV3_CHANGE_TO_EXCLUDE(%.2X)\n",type);
      break;
    case IGMPV3_ALLOW_NEW_SOURCES:
      fprintf(logfile,"|                                   IGMP Record Type       : IGMPV3_ALLOW_NEW_SOURCES(%.2X)\n",type);
      break;
    case IGMPV3_BLOCK_OLD_SOURCES:
      fprintf(logfile,"|                                   IGMP Record Type       : IGMPV3_BLOCK_OLD_SOURCES(%.2X)\n",type);
      break;
  }


}
