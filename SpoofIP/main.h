// IP header's structure
typedef struct ip_hdr
{
	unsigned char ip_header_len : 4; // 4-bit header length (in 32-bit words)
	unsigned char ip_version : 4;   // 4-bit IPv4 version
	unsigned char ip_tos;          // IP type of service
	unsigned short ip_total_length; // Total length
	unsigned short ip_id;          // Unique identifier

	unsigned char ip_frag_offset : 5; // Fragment offset field

	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;

	unsigned char ip_frag_offset1; //fragment offset

	unsigned char ip_ttl;          // Time to live
	unsigned char ip_protocol;     // Protocol(TCP,UDP etc)
	unsigned short ip_checksum;    // IP checksum
	unsigned int ip_srcaddr;       // Source address
	unsigned int ip_destaddr;      // Source address
} IPV4_HDR, *PIPV4_HDR, FAR * LPIPV4_HDR;

// UDP header's structure
typedef struct udp_hdr {
	unsigned short int udph_srcport;
	unsigned short int udph_destport;
	unsigned short int udph_len;
	unsigned short int udph_chksum;
} UDP_HDR;

//Pseudo header UDP IPv4
struct pseudo_header
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short int udp_length;
};

unsigned short csum(unsigned short *data, int len);
IPV4_HDR* createHeaderIP(char* buffer, const char* src_addr, const char* dst_addr, const int data_len);
UDP_HDR* createHeaderUDP(char* buffer, const char* srcport, const char* dstport, const int data_len);
void calculateUDPChecksum(UDP_HDR *udp, IPV4_HDR *ip, unsigned char *data, const int data_len);