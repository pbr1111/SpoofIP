#include <stdio.h>
#include <stdint.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define BUFFER_LENGTH 8192 // Buffer length

#pragma comment(lib, "Ws2_32.lib")

// IP header's structure (little endian)
typedef struct ip_hdr {
	uint8_t ip_header_len : 4;
	uint8_t ip_version : 4;
	uint8_t ip_tos;
	uint16_t ip_total_length;

	uint16_t ip_id;
	uint16_t ip_frag_offset;
#define	IP_DF 0x4000 // Don't fragment flag
#define	IP_MF 0x2000 // More fragments flag

	uint8_t ip_ttl;
	uint8_t ip_protocol;
	uint16_t ip_checksum;

	uint32_t ip_srcaddr;
	uint32_t ip_destaddr;
} IPV4_HDR, *PIPV4_HDR, FAR * LPIPV4_HDR;

// UDP header's structure
typedef struct udp_hdr {
	uint16_t udph_srcport;
	uint16_t udph_destport;
	uint16_t udph_len;
	uint16_t udph_chksum;
} UDP_HDR;

//Pseudo header UDP IPv4
struct pseudo_header {
	uint32_t source_address;
	uint32_t dest_address;
	uint8_t placeholder;
	uint8_t protocol;
	uint16_t udp_length;
};

uint16_t calculateIPChecksum(uint16_t *data, int len);
IPV4_HDR* createHeaderIP(char* buffer, const char* src_addr, const char* dst_addr, const int data_len);
UDP_HDR* createHeaderUDP(char* buffer, const char* srcport, const char* dstport, const int data_len);
void calculateUDPChecksum(UDP_HDR *udp, IPV4_HDR *ip, uint8_t *data, const int data_len);