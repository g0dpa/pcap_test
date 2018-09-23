#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include <arpa/inet.h>

#define ETHERTYPE_IPv4 0x0800
#define ETHERTYPE_IPv6 0x86DD
#define ETHERTYPE_ARP  0x0806

struct eth_hdr {
	uint8_t dest[6];
	uint8_t src[6];
	uint16_t type;
	uint8_t data[0];
} __attribute__((packed));

#define IPV4_FIND_IHL(XX)  ((uint8_t)(((XX)->VER_IHL & 0x0F) << 2))

struct ipv4_hdr {
	uint8_t VER_IHL; // Version(4) + IHL(4)
	uint8_t TOS;
	uint16_t length;
	uint16_t id;
	uint16_t flag_frag; // Flags(0, DF, MF) + Fragment offset
	uint8_t TTL;
	uint8_t protocol;
	uint16_t header_checksum;
	uint8_t src[4];
	uint8_t dest[4];
	uint8_t data[0];
};

// THL >> 4(/16) << 5(*32) >> 3(/8)
#define TCP_FIND_THL(XX) ((uint8_t)((((uint8_t*)(&(XX)->HRF))[0] & 0xF0) >> 2))

struct tcp_hdr {
	uint16_t src;
	uint16_t dest;
	uint32_t seq_number;
	uint32_t ack_number;
	uint16_t HRF; // THL, Reserved, Flags
	uint16_t window_size;
	uint16_t tcp_checksum;
	uint16_t urg_pointer;
	uint8_t payload[0];
};

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test en0\n");
  exit(-1);
}

char errbuf[PCAP_ERRBUF_SIZE];

void pk_start(const u_char*, int len);
void pk_eth(const struct eth_hdr* packet_eth);
void pk_ipv4(const struct ipv4_hdr* packet_ipv4);
void pk_tcp(const struct tcp_hdr*, uint16_t length);

void pk_print_payload(const uint8_t*, uint32_t len);

int main(int argc, char* argv[]){
  /* check there exists argv[1] */
  if(argc != 2) usage();

  /* read packet from argv[1] */
  pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
	//pcap_t* handle = pcap_open_offline(argv[1],errbuf);
	if (handle == NULL) {
    fprintf(stderr, "Cannot Open Device %s: %s\n", argv[1], errbuf);
    return -1;
  }

  while (1) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    /* let's start to analyze packet */
    pk_start(packet, header->caplen);
  }
  return 0;
}

void pk_start(const u_char* packet, int len){
  /* print length of packet */
	printf("Packet length: %u\n", len);

	/* let's check ethernet header */
	pk_eth((const struct eth_hdr*)packet);
}

void pk_eth(const struct eth_hdr* packet_eth){
  printf("Layer: DataLink - Ethernet\n");

  /* print src */
  printf("Src: ");
	for (int i = 0; i < 6; i++) {
		printf("%s%02X", (i>0 ? ":" : ""), packet_eth->src[i]);
	}
  /* print dst */
  printf("\tDst: ");
  for (int i = 0; i < 6; i++) {
		printf("%s%02X", (i>0 ? ":" : ""), packet_eth->dest[i]);
	}
  puts("");

  switch (ntohs(packet_eth->type)){
    case ETHERTYPE_ARP:
      printf("Ethertype: ARP\n");
      break;
    case ETHERTYPE_IPv4:
  		printf("Ethertype: IPv4\n");
  		pk_ipv4((const struct ipv4_hdr*)packet_eth->data);
  		break;
  	case ETHERTYPE_IPv6:
  		printf("Ethertype: IPv6\n");
  		break;
  	default:
  		printf("Ethertype: Unknown\n");
  		break;
  }
	puts("");
}

/*print Network Layer */
void pk_ipv4(const struct ipv4_hdr *packet_ipv4){
  printf("Layer: Network - IP\n");

  /* print src */
  printf("Src: ");
  for (int i = 0; i < 4; i++) {
    printf("%s%d", (i>0 ? "." : ""), packet_ipv4->src[i]);
  }
  /* print dst */
  printf("\tDst: ");
  for (int i = 0; i < 4; i++) {
    printf("%s%d", (i>0 ? "." : ""), packet_ipv4->dest[i]);
  }
  puts("");

  /* check option field */
  uint8_t ihl = IPV4_FIND_IHL(packet_ipv4);
  if (ihl < 20) {
    fprintf(stderr, "IHL is too small to call packet valid\n");
  }
  else if (ihl == 20) printf("No option for IPv4\n");
  else printf("IPv4 option. IHL: %d\n", ihl);

  /* check Protocol ID */
  switch (packet_ipv4->protocol) {
  case IPPROTO_TCP:
    printf("IPv4 protocol ID: TCP\n");
    pk_tcp((const struct tcp_hdr*)&packet_ipv4->data[ihl - 20], ntohs(packet_ipv4->length) - ihl);
    break;
  case IPPROTO_UDP:
    printf("IPv4 protocol ID: UDP\n");
    break;
  case IPPROTO_ICMP:
    printf("IPv4 protocol ID: ICMP\n");
    break;
  default:
    printf("IPv4 protocol: Unknown\n");
    break;
  }
  puts("");
}

/* print Transport Layer */
void pk_tcp(const struct tcp_hdr *packet_tcp, uint16_t length){
  printf("Layer: Transport - TCP\n");
  /* print port */
  printf("Src Port: %d\t\t",ntohs(packet_tcp->src));
  printf("Dst Port: %d\n",ntohs(packet_tcp->dest));

	/* check header length */
	uint8_t hl = TCP_FIND_THL(packet_tcp);
	if (hl > 60) {
    fprintf(stderr, "HL is too big to call packet valid\n");
  } else if (hl < 20) {
    fprintf(stderr, "HL is too small to call packet valid\n");
  }

	/* print data length */
	uint32_t len = length - hl;
	printf("TCP data length: %u\n", len);

	/* cut payload */
	if (len > 16) len = 16;

	/* prints payload as hexademical */
	printf("Payload(Cut by 16Byte): ");
	pk_print_payload(&packet_tcp->payload[hl - 20], len);
}

/* print payload as hexademical */
void pk_print_payload(const uint8_t *Data, uint32_t len) {
	for (uint32_t i = 0; i < len; i++) {
		printf("%s%02X", (i > 0 ? " " : ""), Data[i]);
	}
  puts("");
}
