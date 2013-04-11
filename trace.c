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
  
  result = pcap_next_ex(fp, &header, &packet);
  while (result > -1) {
    printf("\nPacket number: %d  Packet Len: %ld\n\n", cnt, (long int)header->len);
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
  UDP *udp;
  ICMP *icmp;
  u_int size_ip = 0;
  u_short ether_type;
    
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

  	switch(ip->protocol) {
  		case IPPROTO_TCP:
      	tcp = (TCP*)(pkt_data + SIZE_ETHERNET + size_ip);
      	printTCP(tcp, ip, pkt_data);
  			break;
  		case IPPROTO_UDP:
      	udp = (UDP*)(pkt_data + SIZE_ETHERNET + size_ip);
      	printUDP(udp);
  			break;
  		case IPPROTO_ICMP:
      	icmp = (ICMP*)(pkt_data + SIZE_ETHERNET + size_ip);
      	printICMP(icmp);
  			return;
  		case IPPROTO_IP:
  			printf("\t\tProtocol: IP\n");
  			break;
  		default:
  			printf("\t\tProtocol: unknown\n");
  			break;
  	}
	}
}



void printTCP(TCP *tcp, IP *ip, const u_char* packet) 
{

  TCP_PSEUDO pseudo;
	int checksum_result;

	int ip_total_length = ntohs(ip->tot_len);
	int size_ip = (ip->ip_vhl & 0x0f) * 4;
	int tcp_size = ip_total_length - size_ip;
	int check_block_size = tcp_size + sizeof(TCP_PSEUDO);
	char check_block[check_block_size];
  
  pseudo.src = ip->saddr;
  pseudo.dst = ip->daddr;
  pseudo.zero = 0;
  pseudo.protocol = ip->protocol;
  pseudo.tcplen = htons(tcp_size);
  
  /*
  printf("ip_total_len: \t\t%d \n", ip_total_length);
  printf("size_ip: \t\t%d\n", size_ip);
  printf("pseudo_header_size: \t%d\n", sizeof(TCP_PSEUDO));
  printf("tcp_len: \t\t%d\n", tcp_size);
  printf("check_block_size: \t%d\n ",  check_block_size);
  */

  memcpy(check_block, &pseudo, sizeof(TCP_PSEUDO));   
  memcpy(check_block + sizeof(TCP_PSEUDO), packet + SIZE_ETHERNET + size_ip, tcp_size);

  checksum_result = in_cksum((unsigned short *)(check_block), check_block_size);

  printf("\tTCP Header\n");
  printf("\t\tSource Port:  %d\n", ntohs(tcp->source_port));
  printf("\t\tDest Port:  %d\n", ntohs(tcp->dest_port));
  printf("\t\tSequence Number: %u\n", ntohl(tcp->th_seq));
  printf("\t\tACK Number: %u\n", ntohl(tcp->th_ack));
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
  if(!checksum_result) {
    printf("\t\tChecksum: Correct (0x%x)\n", ntohs(tcp->checksum));  
  } else {
    printf("\t\tChecksum: Incorrect (0x%x)\n", ntohs(tcp->checksum));
  }

  
  
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
			break;
		case IPPROTO_ICMP:
			printf("\t\tProtocol: ICMP\n");
			break;
		case IPPROTO_IP:
			printf("\t\tProtocol: IP\n");
			break;
		default:
			printf("\t\tProtocol: unknown\n");
			break;
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

void printUDP(UDP *udp) 
{
  printf("\tUDP Header\n");
  printf("\t\tSource Port: %d\n", ntohs(udp->sport));
  printf("\t\tDest Port: %d\n", ntohs(udp->dport));
  printf("\n");	
}

void printICMP(ICMP *icmp) 
{
  printf("\tICMP Header\n");
  if(!icmp->type) {
    printf("\t\tType: Reply\n");
  } else {
    printf("\t\tType: Request\n");
  }
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