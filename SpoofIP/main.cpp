#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>

#include "main.h"

#define PCKT_LEN 8192

#pragma comment(lib, "Ws2_32.lib")

int main(int argc, char *argv[])
{
	WSADATA wsock;
	SOCKET sd = INVALID_SOCKET;
	char buffer[PCKT_LEN];
	struct sockaddr_in sin, din;
	const int optval = 1;

	//Buffer to 0
	memset(buffer, 0, sizeof(buffer));

	if (argc != 5)
	{
		printf("- Invalid parameters!\n");
		printf("- Usage %s <source hostname/IP> <source port> <target hostname/IP> <target port>\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	//Initialise WinSock2
	if (WSAStartup(MAKEWORD(2, 2), &wsock) != NO_ERROR)
	{
		printf("WSAStartup() failed %u", WSAGetLastError());
		exit(EXIT_FAILURE);
	}

	//Create UDP socket
	if ((sd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP)) == INVALID_SOCKET)
	{
		printf("socket() error %u", WSAGetLastError());
		WSACleanup();
		exit(EXIT_FAILURE);
	}

	//Put socket in RAW Mode.
	if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, (char *)&optval, sizeof(optval)) == SOCKET_ERROR)
	{
		printf("setsockopt() error %u", WSAGetLastError());
		WSACleanup();
		exit(EXIT_FAILURE);
	}

	//Assign addresses
	sin.sin_family = AF_INET;
	din.sin_family = AF_INET;
	sin.sin_port = htons(atoi(argv[2]));
	din.sin_port = htons(atoi(argv[4]));
	inet_pton(AF_INET, argv[1], &(sin.sin_addr));
	inet_pton(AF_INET, argv[3], &(din.sin_addr));


	//Data
	char *data = "Hello World!";
	int payload = strlen(data);

	//Create headers
	IPV4_HDR *ip_hdr = createHeaderIP(buffer, argv[1], argv[3], payload);
	UDP_HDR *udp_hdr = createHeaderUDP(buffer, argv[2], argv[4], payload);

	//Add data to the buffer
	memcpy(buffer + sizeof(IPV4_HDR) + sizeof(UDP_HDR), data, payload);
	
	calculateUDPChecksum(udp_hdr, ip_hdr, (unsigned char *)data, payload);


	printf("Using Source IP: %s port: %u, Target IP: %s port: %u.\n", argv[1], atoi(argv[2]), argv[3], atoi(argv[4]));

	for (int count = 0; count < 1; count++)
	{
		if (sendto(sd, buffer, sizeof(IPV4_HDR) + sizeof(UDP_HDR) + payload, 0, (struct sockaddr *)&sin, sizeof(sin)) == SOCKET_ERROR)
		{
			printf("sendto() error %u", WSAGetLastError());
			WSACleanup();
			exit(EXIT_FAILURE);
		}

		printf("Count #%u - sendto() is OK.\n", count);
		Sleep(2);
	}

	closesocket(sd);
	WSACleanup();
	return 0;
}

unsigned short csum(unsigned short *data, int len)
{
	long sum = 0;

	while (len > 1){
		sum += *data++;
		if (sum & 0x80000000)  
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}

	if (len)
		sum += (unsigned short)*((unsigned char *)data);

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return ~sum;
}

IPV4_HDR* createHeaderIP(char* buffer, const char* src_addr, const char* dst_addr, const int data_len)
{
	IPV4_HDR *ip_hdr = (IPV4_HDR *) buffer;
	ip_hdr->ip_header_len = 5;
	ip_hdr->ip_version = 4;
	ip_hdr->ip_tos = 0;
	ip_hdr->ip_total_length = htons(sizeof(IPV4_HDR) + sizeof(UDP_HDR) + data_len);
	ip_hdr->ip_id = htons(2);
	ip_hdr->ip_frag_offset = 0;
	ip_hdr->ip_frag_offset1 = 0;
	ip_hdr->ip_reserved_zero = 0;
	ip_hdr->ip_dont_fragment = 1;
	ip_hdr->ip_more_fragment = 0;
	ip_hdr->ip_ttl = 64;
	ip_hdr->ip_protocol = IPPROTO_UDP;
	inet_pton(AF_INET, src_addr, &(ip_hdr->ip_srcaddr));
	inet_pton(AF_INET, dst_addr, &(ip_hdr->ip_destaddr));
	ip_hdr->ip_checksum = htons(csum((unsigned short *)ip_hdr, sizeof(IPV4_HDR)));

	return ip_hdr;
}


UDP_HDR* createHeaderUDP(char* buffer, const char* srcport, const char* dstport, const int data_len)
{
	UDP_HDR *udp = (UDP_HDR *)(buffer + sizeof(IPV4_HDR));

	udp->udph_srcport = htons(atoi(srcport));
	udp->udph_destport = htons(atoi(dstport));
	udp->udph_len = htons(sizeof(UDP_HDR) + data_len);
	udp->udph_chksum = 0;

	return udp;
}


void calculateUDPChecksum(UDP_HDR *udp_header, IPV4_HDR *ip_header, unsigned char *data, const int data_len)
{
	struct pseudo_header psh;
	psh.source_address = ip_header->ip_srcaddr;
	psh.dest_address = ip_header->ip_destaddr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_UDP;
	psh.udp_length = htons(sizeof(UDP_HDR) + data_len);

	int psize = sizeof(struct pseudo_header) + sizeof(UDP_HDR) + data_len;
	char *pseudogram = (char *)malloc(psize);

	memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), udp_header, sizeof(UDP_HDR) + data_len);

	udp_header->udph_chksum = csum((unsigned short*)pseudogram, psize);
	free(pseudogram);
}