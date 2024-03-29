#ifndef TRACE_HEADER
#define TRACE_HEADER

#include <pcap.h>
#include <netinet/tcp.h>

//#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET 14
#define LINE_LEN 16
#define TCPSYN_LEN 20

#define ARP_REQUEST 1
#define ARP_REPLY 2 

#define FLAG_FIN 0x01
#define FLAG_SYN 0x02
#define FLAG_RST 0x04

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)


#pragma pack(1)
/* Ethernet header */
typedef struct ethernet_struct {
  u_char dest_host[ETHER_ADDR_LEN];
  u_char source_host[ETHER_ADDR_LEN];
  u_short type;
} ETHERNET;


typedef struct ip_struct {
  u_char ip_vhl;
  u_int8_t  tos;
  u_int16_t tot_len;
  u_int16_t id;
  u_int16_t frag_off;
  u_int8_t  ttl;
  u_int8_t  protocol;
  u_int16_t check;
  u_int32_t saddr;
  u_int32_t daddr;
  u_int32_t options;
} IP;


typedef struct arp_struct { 
  u_int16_t hardware_type;
  u_int16_t protocol_type;
  u_char hardware_address_len;
  u_char protocol_len;
  u_int16_t op_code;
  u_char send_mac[6];
  u_char send_ip[4];
  u_char rec_mac[6];
  u_char rec_ip[4];
} ARP; 

#pragma pack(1)
typedef struct tcp_struct {
  u_short source_port;
  u_short dest_port;
  u_int32_t th_seq;
  u_int32_t th_ack;
  u_char offset;	
	u_char flags;
	u_short window_size;
	u_short checksum;
	u_short urgent_pointer;
} TCP;

typedef struct tcp_pseudo_struct {
  u_int32_t src;
  u_int32_t dst;
  u_char zero;
  u_char protocol;
  u_int16_t tcplen;
} TCP_PSEUDO;

typedef struct udp_struct{
    u_short sport;
    u_short dport;
    u_short len;
    u_short crc;
} UDP;

typedef struct icmp_struct{
    u_char type;
    u_char code;
    u_short checksum;
} ICMP;


void printEthernet(ETHERNET *ethernet);
void printIP(IP *ip);
void printTCP(TCP *tcp, IP *ip, const u_char* packet);
void printARP(ARP *arp);
void printUDP(UDP *udp);
void printICMP(ICMP *icmp);


void handle_packet(const struct pcap_pkthdr *header, const u_char *pkt_data);


#endif