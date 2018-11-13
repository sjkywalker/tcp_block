/* Copyright © 2018 James Sung. All rights reserved. */
// usage: ./tcp_block <interface>

#include "functions.h"


char divisor[] = "*******************************************************************";


int main(int argc, char *argv[])
{
	if (argc != 2)
	{
		usage();
		return -1;
	}

	char   *dev = argv[1];
	char    errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	//pcap_t *handle = pcap_open_offline("path/to/pcap/file", errbuf);
	//pcap_t *handle = pcap_open_offline("/home/skywalker/Desktop/JK/cydf/3_2/gilgil/180920/pcap_files/tcp-port-80-test.gilgil.pcap", errbuf);
	// toggle `handle` to use either real-time capturing or existing pcap file

	uint32_t SEQ_NUM;
	uint32_t ACK_NUM;

	uint8_t *my_MAC_array = (uint8_t *)calloc(1, 6 * sizeof(uint8_t));

	if (handle == NULL)
	{
		fprintf(stderr, "[-] Couldn't open device %s: %s\n", dev, errbuf);

		return -1;
	}

	GET_MY_MAC(my_MAC_array, dev);

	printf("[+] Receiving packets...\n\n");

	while (true)
	{
		struct pcap_pkthdr *header;
		const uint8_t      *packet;
		int res = pcap_next_ex(handle, &header, &packet);
		
		if (res == 0)               { continue; }
		if (res == -1 || res == -2) { break; }
		
		struct libnet_ethernet_hdr *PCKT_ETH_HDR = (struct libnet_ethernet_hdr *)packet;

		uint16_t PCKT_ETHERTYPE = ntohs(PCKT_ETH_HDR->ether_type);

		uint16_t PCKT_IPPROTO;

		uint32_t PCKT_PRINTBASE;
		uint32_t PCKT_DATAOFFSET;
		uint32_t PCKT_DATALEN;

		// only TCP/IP packets are considered
		if (PCKT_ETHERTYPE != ETHERTYPE_IP) { continue; }

		struct libnet_ipv4_hdr *PCKT_IP_HDR = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));

		if (PCKT_IP_HDR->ip_v != 4)           { continue; }
		if (PCKT_IP_HDR->ip_p != IPPROTO_TCP) { continue; }

		struct libnet_tcp_hdr *PCKT_TCP_HDR = (struct libnet_tcp_hdr *)(packet + sizeof(struct libnet_ethernet_hdr) + (PCKT_IP_HDR->ip_hl << 2));
	
		PCKT_DATAOFFSET = sizeof(struct libnet_ethernet_hdr) + (PCKT_IP_HDR->ip_hl << 2) + (PCKT_TCP_HDR->th_off << 2);
		PCKT_PRINTBASE = (PCKT_DATAOFFSET >> 4) << 4;
		PCKT_DATALEN = ntohs(PCKT_IP_HDR->ip_len) - (PCKT_IP_HDR->ip_hl << 2) - (PCKT_TCP_HDR->th_off << 2);

		uint8_t MY_PCKT_SIZE = sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_tcp_hdr) + sizeof(struct libnet_tcp_hdr);
		uint8_t *my_packet = (uint8_t *)calloc(1, MY_PCKT_SIZE + 999);

		struct libnet_ethernet_hdr *MY_PCKT_ETH_HDR = (struct libnet_ethernet_hdr *)my_packet;
		struct libnet_ipv4_hdr     *MY_PCKT_IP_HDR  = (struct libnet_ipv4_hdr *)(my_packet + sizeof(struct libnet_ethernet_hdr));
		struct libnet_tcp_hdr      *MY_PCKT_TCP_HDR = (struct libnet_tcp_hdr *)(my_packet + sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr));

		SEQ_NUM = ntohl(PCKT_TCP_HDR->th_seq);
		ACK_NUM = ntohl(PCKT_TCP_HDR->th_ack);

		// forward RST
		INIT_RST_PCKT(my_packet, packet, my_MAC_array);
		for (int i = 0; i < 5; i++) { pcap_sendpacket(handle, my_packet, MY_PCKT_SIZE); }
				
		puts("tcp/http forward rst");
		print_packet_info(my_packet, MY_PCKT_SIZE); puts("\n");

		// backward: rst or fin: reset{shost, dhost}, flip{ip, port}
		memcpy(MY_PCKT_ETH_HDR->ether_dhost, PCKT_ETH_HDR->ether_shost, 6);

		(MY_PCKT_IP_HDR->ip_src).s_addr = (PCKT_IP_HDR->ip_dst).s_addr;
		(MY_PCKT_IP_HDR->ip_dst).s_addr = (PCKT_IP_HDR->ip_src).s_addr;
		MY_PCKT_IP_HDR->ip_sum = 0;
		MY_PCKT_IP_HDR->ip_sum = htons(ip_hdr_checksum((uint16_t *)MY_PCKT_IP_HDR));

		MY_PCKT_TCP_HDR->th_sport = PCKT_TCP_HDR->th_dport;
		MY_PCKT_TCP_HDR->th_dport = PCKT_TCP_HDR->th_sport;
		MY_PCKT_TCP_HDR->th_seq = htonl(ACK_NUM);
		MY_PCKT_TCP_HDR->th_ack = htonl(SEQ_NUM + PCKT_DATALEN);

		// consider phantom byte
		if ((PCKT_TCP_HDR->th_flags & TH_SYN) || (PCKT_TCP_HDR->th_flags & TH_FIN))
		{
			MY_PCKT_TCP_HDR->th_ack = htonl(SEQ_NUM + 1);
		}

		// if HTTP, change backward RST -> FIN
		if (is_http_request(PCKT_TCP_HDR))
		{
			//char http_message[99999] = "HTTP/1.1 403 Forbidden\r\n\r\nBlocked!\r\n\r\n";
			//char http_message[] = "Blocked!\r\n";
			char http_message[99999] = "HTTP/1.1 403 Forbidden\r\n\r\n<!DOCTYPE html><html><head>blocked</head><body><p>Blocked</p></body></html>";

			if (strlen(http_message) % 2 == 1) { http_message[strlen(http_message) + 1] = 0; http_message[strlen(http_message)] = '\n'; }
			
			memcpy(my_packet + MY_PCKT_SIZE, http_message, strlen(http_message));
			MY_PCKT_IP_HDR->ip_len = htons(40 + strlen(http_message));
			MY_PCKT_SIZE = MY_PCKT_SIZE + strlen(http_message);
			MY_PCKT_TCP_HDR->th_flags = TH_FIN + TH_ACK;
			puts("http backward fin");
		}

		else { puts("tcp backward rst"); }

		MY_PCKT_IP_HDR->ip_sum = 0;
		MY_PCKT_IP_HDR->ip_sum = htons(ip_hdr_checksum((uint16_t *)MY_PCKT_IP_HDR));
		MY_PCKT_TCP_HDR->th_sum = 0;
		MY_PCKT_TCP_HDR->th_sum = htons(tcp_hdr_checksum((uint16_t *)MY_PCKT_IP_HDR, MY_PCKT_SIZE - sizeof(struct libnet_ethernet_hdr) - sizeof(struct libnet_ipv4_hdr)));
		for (int i = 0; i < 5; i++) { pcap_sendpacket(handle, my_packet, MY_PCKT_SIZE); }
		print_packet_info(my_packet, MY_PCKT_SIZE); puts("\n");

		printf("<%u bytes captured>\nTCP data len: %d\n", header->caplen, PCKT_DATALEN);

		print_eth_info(PCKT_ETH_HDR); puts("");
		print_ip_info(PCKT_IP_HDR); puts("");
		print_tcp_info(PCKT_TCP_HDR); puts("");
		//print_data_info(packet, PCKT_PRINTBASE, PCKT_DATAOFFSET, PCKT_DATALEN); puts("\n");
		
		puts("Captured packet");
		print_packet_info(packet, header->caplen); puts("\n");

		printf("%s\n", divisor);

		free(my_packet);
	}

	printf("[*] Program exiting...\n");

	// printf("libnet_ethernet_hdr: %lu\n", sizeof(struct libnet_ethernet_hdr));
	// printf("libnet_ipv4_hdr: %lu\n", sizeof(struct libnet_ipv4_hdr));
	// printf("libnet_tcp_hdr: %lu\n", sizeof(struct libnet_tcp_hdr));

	free(my_MAC_array);

	return 0;
}

