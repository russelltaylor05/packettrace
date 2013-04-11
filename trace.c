#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include "trace.h"
#include "checksum.h"


int main(int argc, char *argv[])
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *fp;
  struct pcap_pkthdr *header;
  const u_char *packet;
  int result = 1;
  int cnt = 1;
  
  if (argc != 2) {
    printf("usage: %s filename\n", argv[0]);
    return -1;  
  }
  if ( (fp = pcap_open_offline(argv[1], errbuf) ) == NULL) {
    fprintf(stderr,"\nError opening dump file\n");
    return -1;
  }  
  
  //pcap_loop(fp, 0, dispatcher_handler, NULL);  
  
  result = pcap_next_ex(fp, &header, &packet);
  while (result > -1) {
    //printf("%d,",result);
    printf("Packet number: %d  Packet Len: %ld\n\n", cnt, (long int)header->len);
    handle_packet(header, packet);
    
    result = pcap_next_ex(fp, &header, &packet);
    cnt++;
  }
  if(result == -1) {
    pcap_geterr(fp);    
  }
  
  pcap_close(fp);
  return(0);
}

void handle_packet(const struct pcap_pkthdr *header, const u_char *pkt_data)
{

  ETHERNET *ethernet;
  IP *ip;
  TCP *tcp;
  ARP *arp;
  u_int size_ip = 0;
  u_short ether_type;
  
  
  //printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);
    
	ethernet = (ETHERNET*)(pkt_data);
	ether_type = ntohs(ethernet->type);
	printEthernet(ethernet);
	
	if(ether_type == ETHERTYPE_ARP) {
  	arp = (ARP*)(pkt_data + 14); 
  	printARP(arp);  	

	} else {
  	
  	ip = (IP*)(pkt_data + SIZE_ETHERNET);
  	printIP(ip);
  	
  	size_ip = (ip->ip_vhl & 0x0f) * 4;
  	printf("size %d\n", size_ip);
  	
  	tcp = (TCP*)(pkt_data + SIZE_ETHERNET + size_ip);
  	printTCP(tcp);
  	
	}
	
        
  printf("\n\n");
    
}

void printARP(ARP *arp) 
{
  char *send_mac, *send_ip, *rec_mac, *rec_ip;  
  
  send_mac = ether_ntoa((const struct ether_addr *)arp->send_mac);
  rec_mac = ether_ntoa((const struct ether_addr *)arp->rec_mac);
  send_ip = inet_ntoa(*(struct in_addr *)&(arp->send_ip));
  rec_ip = inet_ntoa(*(struct in_addr *)&(arp->rec_ip));
  
  printf("  ARP header \n");
  if(ntohs(arp->op_code) == ARP_REQUEST) {
    printf("    Opcode: Request\n");  
  } else {
    printf("    Opcode: Reply\n");
  }  
  printf("    Sender MAC: %s\n", send_mac);
  printf("    Sender IP: %s\n", send_ip);
  printf("    Target MAC: %s\n", rec_mac);
  printf("    Target IP: %s\n", rec_ip);
}

void printTCP(TCP *tcp) 
{

  printf("  TCP Header \n");
  printf("    Source Port:  %d\n", tcp->source_port);
  printf("    Dest Port:  %d\n", tcp->dest_port);
  /*
  printf("    Sequence Number: 120759613\n");
  printf("    ACK Number: 0\n");
  printf("    SYN Flag: Yes\n");
  printf("    RST Flag: No\n");
  printf("    FIN Flag: No\n");
  printf("    Window Size: 16384\n");
  printf("    Checksum: Correct (0x5aba)\n");
  */
}

void printIP(IP *ip)
{
  char *addr;  
	unsigned short checksum_result;
	int checksum_size;

	checksum_size = (ip->ip_vhl & 0x0f) * 4;
  checksum_result = in_cksum((unsigned short *)ip, checksum_size);

  printf("  IP Header\n");
  printf("    TOS: 0x%x\n", ip->tos);
  printf("    TTL: %d\n", ip->ttl);
  printf("    Protocol: %d\n", ip->protocol);
  if(!checksum_result) {
    printf("    Checksum: Correct (0x%x)\n", ip->check);  
  } else {
    printf("    Checksum: Incorrect (0x%x)\n", ip->check);
  }  
  addr = inet_ntoa(*(struct in_addr *)&(ip->saddr));
  printf("    Sender IP: %s\n", addr);
  addr = inet_ntoa(*(struct in_addr *)&(ip->daddr));
  printf("    Dest  IP : %s\n", addr);
  printf("\n");
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