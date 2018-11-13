/* Copyright © 2018 James Sung. All rights reserved. */

#include "functions.h"

void usage(void)
{
	printf("[-] Syntax: ./tcp_block <interface>\n");
	printf("[-] Sample: ./tcp_block wlan0\n");
	
	return;
}

void GET_MY_MAC(uint8_t *my_MAC_array, char *interface)
{
	struct ifreq s;
	int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
	
	strcpy(s.ifr_name, interface);
	if (!ioctl(fd, SIOCGIFHWADDR, &s))
	{
		memcpy(my_MAC_array, s.ifr_addr.sa_data, 6 * sizeof(uint8_t));
	}

	return;
}

void print_mac_addr(uint8_t *mac)
{
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	return;
}

void print_eth_info(struct libnet_ethernet_hdr *PCKT_ETH_HDR)
{
	printf("[Source      MAC Address] "); print_mac_addr(PCKT_ETH_HDR->ether_shost);
	printf("[Destination MAC Address] "); print_mac_addr(PCKT_ETH_HDR->ether_dhost);

	return;
}

void print_ip_addr(struct in_addr ip)
{
	printf("%s\n", inet_ntoa(ip));

	return;
}

void print_ip_info(struct libnet_ipv4_hdr *PCKT_IP_HDR)
{
	printf("[Source      IP  Address] "); print_ip_addr(PCKT_IP_HDR->ip_src);
	printf("[Destination IP  Address] "); print_ip_addr(PCKT_IP_HDR->ip_dst);
	
	return;
}

void print_port_number(uint16_t port)
{
	printf("%5d\n", ntohs(port));

	return;
}

void print_tcp_info(struct libnet_tcp_hdr *PCKT_TCP_HDR)
{
	printf("[Source      TCP  Port #] "); print_port_number(PCKT_TCP_HDR->th_sport);
	printf("[Destination TCP  Port #] "); print_port_number(PCKT_TCP_HDR->th_dport);

	return;
}

void print_data_info(const uint8_t *packet, uint32_t PCKT_PRINTBASE, uint32_t PCKT_DATAOFFSET, uint32_t PCKT_DATALEN)
{
	printf("[Data]\n");
	//for (int i = PCKT_PRINTBASE; i < (PCKT_DATAOFFSET + 32) && (i < PCKT_DATAOFFSET + PCKT_DATALEN); i++)
	for (int i = PCKT_PRINTBASE; (i < PCKT_DATAOFFSET + PCKT_DATALEN); i++)
	{
		if (i < PCKT_DATAOFFSET) { printf("-- ");}
		else { printf("%02x ", packet[i]); }

		if (i % 16 == 7) { printf(" "); }
		if (i % 16 == 15) { printf("\n"); }
	}

	return;
}

void print_packet_info(const uint8_t *packet, uint32_t PCKT_TOTLEN)
{
	printf("[Data]\n");
	//for (int i = PCKT_PRINTBASE; i < (PCKT_DATAOFFSET + 32) && (i < PCKT_DATAOFFSET + PCKT_DATALEN); i++)
	for (int i = 0; i < PCKT_TOTLEN; i++)
	{
		printf("%02x ", packet[i]);

		if (i % 16 == 7) { printf(" "); }
		if (i % 16 == 15) { printf("\n"); }
	}

	return;
}

bool is_http_request(struct libnet_tcp_hdr *data)
{
	char httpMethods[7][8] = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS"};

	for (int i = 0; i < 6; i++)
	{
		if (!strncmp(httpMethods[i], (const char *)((uint8_t *)data + (data->th_off << 2)), strlen(httpMethods[i]))) // if http packet, set flag
		{
			return 1;
		}
	}

	return 0;
}

uint16_t ip_hdr_checksum(uint16_t *packet_ip_hdr)
{
	uint16_t checksum = 0;
	uint32_t tmp = 0;
	
	for (int i = 0; i < 10; i++)
	{
		tmp += ntohs(*(packet_ip_hdr + i));
	}

	tmp = (tmp - ((tmp >> 16) << 16)) + (tmp >> 16);
	checksum = ~(tmp & 0xFFFF);
	
	return checksum;
}

uint16_t tcp_hdr_checksum(uint16_t *packet_ip_hdr, uint16_t length)
{
	uint16_t checksum = 0;
	uint32_t tmp = 0;
	uint16_t *packet_tcp_hdr = (packet_ip_hdr + 10);

	for (int i = 6; i < 10; i++)
	{
		tmp += ntohs(*(packet_ip_hdr + i));
	}

	tmp += 0x0006;
	tmp += length;

	for (int i = 0; i < (length / 2); i++)
	{
		tmp += ntohs(*(packet_tcp_hdr + i));
	}

	tmp = (tmp - ((tmp >> 16) << 16)) + (tmp >> 16);
	checksum = ~(tmp & 0xFFFF);

	return checksum;
}

void INIT_RST_PCKT(uint8_t *my_packet, const uint8_t *packet, uint8_t *my_MAC_array)
{
	struct libnet_ethernet_hdr *PCKT_ETH_HDR = (struct libnet_ethernet_hdr *)packet;
	struct libnet_ipv4_hdr *PCKT_IP_HDR = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
	struct libnet_tcp_hdr *PCKT_TCP_HDR = (struct libnet_tcp_hdr *)(packet + sizeof(struct libnet_ethernet_hdr) + (PCKT_IP_HDR->ip_hl << 2));

	struct libnet_ethernet_hdr *MY_PCKT_ETH_HDR = (struct libnet_ethernet_hdr *)my_packet;
	struct libnet_ipv4_hdr     *MY_PCKT_IP_HDR  = (struct libnet_ipv4_hdr *)(my_packet + sizeof(struct libnet_ethernet_hdr));
	struct libnet_tcp_hdr      *MY_PCKT_TCP_HDR = (struct libnet_tcp_hdr *)(my_packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr));

	memcpy(MY_PCKT_ETH_HDR->ether_dhost, PCKT_ETH_HDR->ether_dhost, 6);		
	memcpy(MY_PCKT_ETH_HDR->ether_shost, my_MAC_array, 6);
	MY_PCKT_ETH_HDR->ether_type = htons(ETHERTYPE_IP);

	MY_PCKT_IP_HDR->ip_hl = 5;
	MY_PCKT_IP_HDR->ip_v = 4;
	MY_PCKT_IP_HDR->ip_tos = 0;
	MY_PCKT_IP_HDR->ip_len = htons(40);
	MY_PCKT_IP_HDR->ip_id = PCKT_IP_HDR->ip_id;
	MY_PCKT_IP_HDR->ip_off = htons(0x4000);
	MY_PCKT_IP_HDR->ip_ttl = 64;
	MY_PCKT_IP_HDR->ip_p = IPPROTO_TCP;
	MY_PCKT_IP_HDR->ip_sum = 0;
	(MY_PCKT_IP_HDR->ip_src).s_addr = (PCKT_IP_HDR->ip_src).s_addr;
	(MY_PCKT_IP_HDR->ip_dst).s_addr = (PCKT_IP_HDR->ip_dst).s_addr;
	MY_PCKT_IP_HDR->ip_sum = htons(ip_hdr_checksum((uint16_t *)MY_PCKT_IP_HDR));

	MY_PCKT_TCP_HDR->th_sport = PCKT_TCP_HDR->th_sport;
	MY_PCKT_TCP_HDR->th_dport = PCKT_TCP_HDR->th_dport;
	MY_PCKT_TCP_HDR->th_seq = PCKT_TCP_HDR->th_seq;
	MY_PCKT_TCP_HDR->th_ack = PCKT_TCP_HDR->th_ack;
	MY_PCKT_TCP_HDR->th_off = 5;
	MY_PCKT_TCP_HDR->th_flags = TH_RST + TH_ACK;
	MY_PCKT_TCP_HDR->th_win = PCKT_TCP_HDR->th_win;
	MY_PCKT_TCP_HDR->th_sum = 0;
	MY_PCKT_TCP_HDR->th_urp = htons(0);
	MY_PCKT_TCP_HDR->th_sum = htons(tcp_hdr_checksum((uint16_t *)MY_PCKT_IP_HDR, 20));

	return;
}
