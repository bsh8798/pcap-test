#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <netinet/in.h>
#include "header.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

void printInfo(struct ethernet_hdr *ether_hdr, struct ip_hdr *ip_hdr, struct tcp_hdr *tcp_hdr, struct payload *payload, uint payload_length)
{
    printf("source mac: ");
    for(int i = 0; i < 6; i++) {
        printf("%02x", ether_hdr->ether_src_host[i]);
        if(i != 5) {
            printf(":");
        }
    }
    printf("\n");

    printf("destination mac: ");
    for(int i = 0; i < 6; i++) {
        printf("%02x", ether_hdr->ether_dst_host[i]);
        if(i != 5) {
            printf(":");
        }
    }
    printf("\n");

    printf("source ip: ");
    for(int i = 0; i < 4; i++) {
        printf("%d", ip_hdr->ip_src_host[i]);
        if(i != 3) {
            printf(".");
        }
    }
    printf("\n");

    printf("destination ip: ");
    for(int i = 0; i < 4; i++) {
        printf("%d", ip_hdr->ip_dst_host[i]);
        if(i != 3) {
            printf(".");
        }
    }
    printf("\n");

    printf("source port: %d\n", ntohs(tcp_hdr->src_port));
    printf("destination port: %d\n", ntohs(tcp_hdr->dst_port));

    if(payload_length == 0) {
        return;
    }
    printf("TCP payload: ");
    for(uint i = 0; i < payload_length && i < 20; i++) {
        printf("%02x ", payload->data[i]);
    }
    printf("\n\n");
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

    struct ethernet_hdr *ether_hdr;
    struct ip_hdr *ip_hdr;
    struct tcp_hdr *tcp_hdr;
    struct payload *payload;

	while (true) {
        struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
        //printf("%u bytes captured\n", header->caplen);

        ether_hdr = (struct ethernet_hdr*)packet;
        ip_hdr = (struct ip_hdr*)(packet + sizeof(struct ethernet_hdr));
        tcp_hdr = (struct tcp_hdr*)(packet + sizeof(struct ethernet_hdr) + ip_hdr->IHL*4);
        payload = (struct payload*)(packet + sizeof(struct ethernet_hdr) + ip_hdr->IHL*4 + tcp_hdr->header_length*4);
        uint payload_length = header->caplen - (sizeof(struct ethernet_hdr) + ip_hdr->IHL*4 + tcp_hdr->header_length*4);

        if(ip_hdr->protocol == 0x06) {
            printInfo(ether_hdr, ip_hdr, tcp_hdr, payload, payload_length);
        }
	}

	pcap_close(pcap);
}
