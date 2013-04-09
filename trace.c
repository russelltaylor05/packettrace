#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include "trace.h"


int main(int argc, char *argv[])
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *fp;
  //struct pcap_pkthdr header;
  //const u_char *packet;
  

  if (argc != 2) {
    printf("usage: %s filename\n", argv[0]);
    return -1;  
  }  
  
  if ( (fp = pcap_open_offline(argv[1], errbuf) ) == NULL) {
    fprintf(stderr,"\nError opening dump file\n");
    return -1;
  }  
  
	//packet = pcap_next(fp, &header);
	//printf("Jacked a packet with length of [%d]\n", header.len);

  // read and dispatch packets until EOF is reached
  pcap_loop(fp, 0, dispatcher_handler, NULL);  
  
  pcap_close(fp);
    

  return(0);
}

void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data)
{

  ETHERNET *ethernet;
  IP *ip;
  
  /* print pkt timestamp and pkt len */
  //printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);
    
  printf("Packet number: 1  Packet Len: %ld\n", (long int)header->len);
    
	ethernet = (ETHERNET*)(pkt_data);
	printEthernet(ethernet);
	
	ip = (IP*)(pkt_data + SIZE_ETHERNET);
	printIP(ip);
        
  printf("\n\n");
    
}


void printIP(IP *ip)
{
  char *addr;

  printf("  IP Header\n");
  addr = inet_ntoa(*(struct in_addr *)&(ip->saddr));
  printf("    Sender IP: %s\n", addr);
  addr = inet_ntoa(*(struct in_addr *)&(ip->daddr));
  printf("    Dest  IP : %s\n", addr);

}


void printEthernet(ETHERNET *ethernet)
{
  int i = 0;
  u_short ether_type;
  
  printf("  Ethernet Header\n");
  printf("    Dest MAC: ");
  for(i = 0; i < ETHER_ADDR_LEN; i++){
    printf("%x", ethernet->dest_host[i]);
    if(i == ETHER_ADDR_LEN-1) {
      printf("\n");      
    } else {
      printf(":");
    }
  }
  printf("    Source MAC: ");
  for(i = 0; i < ETHER_ADDR_LEN; i++){
    printf("%x", ethernet->source_host[i]);
    if(i == ETHER_ADDR_LEN-1) {
      printf("\n");      
    } else {
      printf(":");
    }
  }
  
  printf("    Type: ");
  ether_type = ntohs(ethernet->type);
  if (ether_type == ETHERTYPE_IP) {
      printf("IP\n");
  } else  if (ether_type == ETHERTYPE_ARP) {
      printf("ARP\n");
  } else  if (ether_type == ETHERTYPE_REVARP) {
      printf("RARP\n");
  } else {
      printf("????\n");
  }  
  
  printf("\n");
  

}