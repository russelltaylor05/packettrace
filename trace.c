#include <stdio.h>
#include <string.h>
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
    printf("\nPacket number: %d  Packet Len: %ld\n\n", cnt, (long int)header->len);
    handle_packet(header, packet);    
    result = pcap_next_ex(fp, &header, &packet);
    cnt++;
    result = -1;
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
  	
  	tcp = (TCP*)(pkt_data + SIZE_ETHERNET + size_ip);
  	printTCP(tcp, ip);
  	  	
	}        
  printf("\n");
    
}



void printTCP(TCP *tcp, IP *ip) 
{

  TCP_PSEUDO pseudo;
	int checksum_size, checksum_result;
	char tcpcsumblock[ sizeof(TCP_PSEUDO) + TCPSYN_LEN ];
  
  /* Fill the pseudoheader so we can compute the TCP checksum*/
  pseudo.src = ip->saddr;
  pseudo.dst = ip->daddr;
  pseudo.zero = 0;
  pseudo.protocol = ip->protocol;
  pseudo.tcplen = htons( sizeof(TCP) );

  memcpy(tcpcsumblock, &pseudo, sizeof(TCP_PSEUDO));   
  memcpy(tcpcsumblock + sizeof(TCP_PSEUDO),tcp, sizeof(TCP));

  checksum_result = in_cksum((unsigned short *)(tcpcsumblock), sizeof(tcpcsumblock));

  printf("\tTCP Header\n");
  printf("\t\tSource Port:  %d\n", ntohs(tcp->source_port));
  printf("\t\tDest Port:  %d\n", ntohs(tcp->dest_port));
  printf("\t\tSequence Number: %d\n", ntohl(tcp->th_seq));
  printf("\t\tACK Number: %d\n", ntohl(tcp->th_ack));
  printf("\t\tSYN Flag: ");
  if(tcp->flags & FLAG_SYN) {
    printf("Yes\n");    
  } else {
    printf("No\n");
  }
  printf("\t\tRST Flag: ");
  if(tcp->flags & FLAG_RST) {
    printf("Yes\n");    
  } else {
    printf("No\n");
  }
  printf("\t\tFIN Flag: ");
  if(tcp->flags & FLAG_FIN) {
    printf("Yes\n");    
  } else {
    printf("No\n");
  }
  printf("\t\tWindow Size: %d\n", ntohs(tcp->window_size));
  printf("\t\tChecksum: %d\n", checksum_result);
  
  
}

void printARP(ARP *arp) 
{
    
  printf("\tARP header\n");
  if(ntohs(arp->op_code) == ARP_REQUEST) {
    printf("\t\tOpcode: Request\n");  
  } else {
    printf("\t\tOpcode: Reply\n");
  }  
  printf("\t\tSender MAC: %s\n", ether_ntoa((const struct ether_addr *)&arp->send_mac));    
  printf("\t\tSender IP: %s\n", inet_ntoa(*(struct in_addr *)&(arp->send_ip)));

  printf("\t\tTarget MAC: %s\n", ether_ntoa((const struct ether_addr *)&arp->rec_mac));
  printf("\t\tTarget IP: %s\n", inet_ntoa(*(struct in_addr *)&(arp->rec_ip)));

}


void printIP(IP *ip)
{
	unsigned short checksum_result;
	int checksum_size;

	checksum_size = (ip->ip_vhl & 0x0f) * 4;
  checksum_result = in_cksum((unsigned short *)ip, checksum_size);

  printf("\tIP Header\n");
  printf("\t\tTOS: 0x%x\n", ip->tos);
  printf("\t\tTTL: %d\n", ip->ttl);
	switch(ip->protocol) {
		case IPPROTO_TCP:
			printf("\t\tProtocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("\t\tProtocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			printf("\t\tProtocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("\t\tProtocol: IP\n");
			return;
		default:
			printf("\t\tProtocol: unknown\n");
			return;
	}  
  if(!checksum_result) {
    printf("\t\tChecksum: Correct (0x%x)\n", ntohs(ip->check));  
  } else {
    printf("\t\tChecksum: Incorrect (0x%x)\n", ntohs(ip->check));
  }
  printf("\t\tSender IP: %s\n", inet_ntoa(*(struct in_addr *)&(ip->saddr)));
  printf("\t\tDest  IP : %s\n", inet_ntoa(*(struct in_addr *)&(ip->daddr)));
  printf("\n");
}


void printEthernet(ETHERNET *ethernet)
{
  u_short ether_type;
  
  
  printf("\tEthernet Header\n");
  printf("\t\tDest MAC: %s\n", ether_ntoa((const struct ether_addr *)&ethernet->dest_host));
  printf("\t\tSource MAC: %s\n", ether_ntoa((const struct ether_addr *)&ethernet->source_host));
  printf("\t\tType: ");
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