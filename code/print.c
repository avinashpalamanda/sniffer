#include "../header/head.h"

void print_eth_packet(unsigned char* buffer,int data_size,FILE* logfile){
  struct ethhdr *eth = (struct ethhdr *)buffer;
  fprintf(logfile,"\n\n###################################################START OF A PACKET########################################################\n");
  fprintf(logfile,"-----------------------------------------------------Ethernet Header------------------------------------------------\n");
  fprintf(logfile , "|                                   Destination Address     : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
  fprintf(logfile , "|                                   Source Address          : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
  fprintf(logfile , "|                                   Protocol                : %x \n", ntohs(eth->h_proto));
  fprintf(logfile,"------------------------------------------------------------------------------------------------------------------\n\n");

}
/*Function Prints the IP header Fields*/
void print_ip_packet(unsigned char* buffer,int data_size,FILE* logfile){
  struct sockaddr_in src;
  struct sockaddr_in dest;

  struct iphdr *iph=(struct iphdr*)(buffer+sizeof(struct ethhdr));

  //Getting Source and Destination Address
  src.sin_addr.s_addr=iph->saddr;
  dest.sin_addr.s_addr=iph->daddr;

  fprintf(logfile,"---------------------------------------------------------IP Header--------------------------------------------------\n");
  fprintf(logfile,"|                                   Version                : %u\n",(unsigned int)iph->version);
  fprintf(logfile,"|                                   Internet Header Length : %u\n",(unsigned int)iph->ihl);
  fprintf(logfile,"|                                   Type of Service        : %u\n",(unsigned int)iph->tos);
  fprintf(logfile,"|                                   Total Length           : %u\n",ntohs(iph->tot_len));
  fprintf(logfile,"|                                   Identification         : %u\n",ntohs(iph->id));
  fprintf(logfile,"|                                   Fragmentation Offset   : %u\n",ntohs(iph->frag_off));
  fprintf(logfile,"|                                   Time To Live           : %u\n",(unsigned int)iph->ttl);
  fprintf(logfile,"|                                   Protocol               : %u\n",(unsigned int)iph->protocol);
  fprintf(logfile,"|                                   Checksum               : %u\n",ntohs(iph->check));
  fprintf(logfile,"|                                   Source Address         : %s\n",inet_ntoa(src.sin_addr));
  fprintf(logfile,"|                                   Destination Address    : %s\n",inet_ntoa(dest.sin_addr));
  fprintf(logfile,"------------------------------------------------------------------------------------------------------------------\n\n");

  fflush(stdout);
  return;
}

/*Printing the TCP Header Fields*/
void print_tcp_packet(unsigned char* buffer,int data_size,FILE* logfile){

  struct iphdr *ip = (struct iphdr *)(buffer+sizeof(struct ethhdr));
  struct tcphdr *tcp=(struct tcphdr*)(buffer + (ip->ihl*4)+sizeof(struct ethhdr));

  fprintf(logfile,"---------------------------------------------------------TCP Header--------------------------------------------------\n");
  fprintf(logfile,"|                                   Source Port            : %u\n",ntohs(tcp->source));
  fprintf(logfile,"|                                   Destination Port       : %u\n",ntohs(tcp->dest));
  fprintf(logfile,"|                                   Sequence Number        : %u\n",ntohl(tcp->seq));
  fprintf(logfile,"|                                   Acknowledgement Number : %u\n",ntohl(tcp->ack_seq));
  fprintf(logfile,"|                                   Length                 : %d\n",(unsigned int)tcp->doff);
  fprintf(logfile,"|                                   Flags\n");
  fprintf(logfile,"|                                             FIN          : %u\n",(unsigned int)tcp->fin);
  fprintf(logfile,"|                                             SYN          : %u\n",(unsigned int)tcp->syn);
  fprintf(logfile,"|                                             RESET        : %u\n",(unsigned int)tcp->rst);
  fprintf(logfile,"|                                             PUSH         : %u\n",(unsigned int)tcp->psh);
  fprintf(logfile,"|                                             ACK          : %u\n",(unsigned int)tcp->ack);
  fprintf(logfile,"|                                             URG          : %u\n",(unsigned int)tcp->urg);
  fprintf(logfile,"|                                   Window                 : %u\n",ntohs(tcp->window));
  fprintf(logfile,"|                                   Check                  : %u\n",ntohs(tcp->check));
  fprintf(logfile,"|                                   Urgent Pointer         : %u\n",ntohs(tcp->urg_ptr));
  fprintf(logfile,"------------------------------------------------------------------------------------------------------------------\n\n");

  fprintf(logfile,"\n");

  fprintf(logfile,"Ethernet Header\n");
  PrintData(buffer ,+sizeof(struct ethhdr),logfile);

  fprintf(logfile,"IP Header\n");
  PrintData(buffer+sizeof(struct ethhdr) , (ip->ihl*4),logfile);

  fprintf(logfile,"TCP Header\n");
  PrintData(buffer+(ip->ihl*4)+sizeof(struct ethhdr) , (tcp->doff*4),logfile);

  fprintf(logfile,"Data Payload\n");
  PrintData(buffer+(ip->ihl*4)+(tcp->doff*4)+sizeof(struct ethhdr) ,( data_size - (tcp->doff*4) - (ip->ihl * 4) -sizeof(struct ethhdr)),logfile);

  fprintf(logfile,"\n###########################################################################################################################\n\n");


  fflush(stdout);
  return;
}

void print_udp_packet(unsigned char* buffer,int data_size,FILE* logfile){

  struct iphdr *ip = (struct iphdr *)(buffer+sizeof(struct ethhdr));
  struct udphdr *udp=(struct udphdr*)(buffer + (ip->ihl*4)+sizeof(struct ethhdr));

  fprintf(logfile,"------------------------------------------------------UDP Header--------------------------------------------------\n");
  fprintf(logfile,"|                                   Source Port            : %d\n",ntohs(udp->source));
  fprintf(logfile,"|                                   Destination Port       : %d\n",ntohs(udp->dest));
  fprintf(logfile,"|                                   Length                 : %d\n",ntohs(udp->len));
  fprintf(logfile,"|                                   Check                  : %d\n",ntohs(udp->check));
  fprintf(logfile,"------------------------------------------------------------------------------------------------------------------\n");

  fprintf(logfile,"\n");

  fprintf(logfile,"Ethernet Header\n");
  PrintData(buffer ,+sizeof(struct ethhdr),logfile);

  fprintf(logfile,"IP Header\n");
  PrintData(buffer+sizeof(struct ethhdr) , (ip->ihl*4),logfile);

  fprintf(logfile,"UDP Header\n");
  PrintData(buffer+(ip->ihl*4)+sizeof(struct ethhdr) , sizeof(struct udphdr),logfile);

  fprintf(logfile,"Data Payload\n");
  PrintData(buffer+(ip->ihl*4)+sizeof(struct udphdr)+sizeof(struct ethhdr) ,( data_size - sizeof(struct udphdr) - (ip->ihl * 4) ),logfile);

  fprintf(logfile,"\n###########################################################################################################################\n\n");

  fflush(stdout);
  return;
}


//Taken from http://www.binarytides.com/packet-sniffer-code-c-linux/ 242-257
  void PrintData (unsigned char* data , int Size,FILE* logfile){
    for(int i=0 ; i < Size ; i++){
      if( i!=0 && i%16==0){//if one line of hex printing is complete...
        fprintf(logfile,"         ");
          for(int j=i-16 ; j<i ; j++){
            if(data[j]>=32 && data[j]<=128)
              fprintf(logfile,"%c",(unsigned char)data[j]); //if its a number or alphabet
            else fprintf(logfile,"."); //otherwise print a dot
            }
            fprintf(logfile,"\n");
      }
      if(i%16==0) fprintf(logfile,"   ");
      fprintf(logfile," %02X",(unsigned int)data[i]);
      if( i==Size-1)  //print the last spaces
      {
        for(j=0;j<15-i%16;j++) fprintf(logfile,"   "); //extra spaces
        fprintf(logfile,"         ");
        for(j=i-i%16 ; j<=i ; j++)
        {
          if(data[j]>=32 && data[j]<=128) fprintf(logfile,"%c",(unsigned char)data[j]);
          else fprintf(logfile,".");
        }
        fprintf(logfile,"\n");
      }
    }
}
