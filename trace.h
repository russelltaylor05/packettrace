#ifndef TRACE_HEADER
#define TRACE_HEADER

#include <pcap.h>

//#define ETHER_ADDR_LEN	6
#define SIZE_ETHERNET 14
#define LINE_LEN 16


/* Ethernet header */
typedef struct ethernet_struct {
  u_char dest_host[ETHER_ADDR_LEN];   /* Destination host address */
  u_char source_host[ETHER_ADDR_LEN];   /* Source host address */
  u_short type;                   /* IP? ARP? RARP? etc */
} ETHERNET;

#pragma pack(1)
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

void printEthernet(ETHERNET *ethernet);
void printIP(IP *ip);

void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data);

#endif