#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "rtmp.h"

#define SNAP_LEN		1518
#define NUM_PACKAGES	-1
#define FILTER			"dst port 1935"

void mac2string(const u_char *bytes, char *out)
{
	sprintf(out, "%02X:%02X:%02X:%02X:%02X:%02X", bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
	return;
}

void ip2string(const u_char *bytes, char *out)
{
	sprintf(out, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
	return;
}

void got_packet(u_char *user, const struct pcap_pkthdr *header, const u_char *bytes)
{
	struct ether_header *ethhdr;
	ethhdr = (struct ether_header*)bytes;
	char smac[0x20], dmac[0x20];

	mac2string(ethhdr->ether_shost, smac);
	mac2string(ethhdr->ether_dhost, dmac);
	//printf("%04X %s => %s\n", ntohs(ethhdr->ether_type), smac, dmac);

	if (ntohs(ethhdr->ether_type) == ETHERTYPE_ARP)
	{
		struct ether_arp *hdr;
		hdr = (struct ether_arp*)(bytes + 14);
		//printf("arp %04X\n", ntohs(hdr->ea_hdr.ar_op));
		if (ntohs(hdr->ea_hdr.ar_pro) == ETHERTYPE_IP)
		{
			char arp_spa[0x20], arp_sha[0x20], arp_tpa[0x20], arp_tha[0x20];
			ip2string(hdr->arp_spa, arp_spa);
			mac2string(hdr->arp_sha, arp_sha);
			ip2string(hdr->arp_tpa, arp_tpa);
			mac2string(hdr->arp_tha, arp_tha);
			printf("ARP: %s(%s) => %s(%s)\n", arp_spa, arp_sha, arp_tpa, arp_tha); 
		}
	}
	else if (ntohs(ethhdr->ether_type) == ETHERTYPE_IP)
	{
		//ip
	}

	/**
    if (strcmp("publish", (const char*)bytes + 0x45))
    {
        printf("%s\n", bytes + 0x96);
    }
	*/
	return;
}

void test()
{
	int socketfd;
	sockaddr_ll addr_in
	int iret;
	char buffer[64];
	socketfd = socket(PF_NDRV, SOCK_RAW, htons(ETHERTYPE_IP));
	if (socketfd < 0)
	{
		fprintf(stderr, "cannot create raw socket \n\n");
	}
	bzero(&addr_in, sizeof(addr_in));
	addr_in.sll_family = PF_NDRV;
	addr_in.sll_ifindex = if_nametoindex("en1");
	iret = sendto(socketfd, buffer, sizeof(buffer), 0, 0, 0);
	printf("%d\n", iret);
	perror("");
	return;
}

int main(int argc, char *argv[])
{
	test();
	return 0;

	char *dev = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	//struct bpf_program fp;

    if (getuid() != 0)
    {
        fprintf(stderr, "must be run as root\n\n");
        return -1;
    }
	if (argc == 2)
	{
		dev = argv[1];
	}
	else if (argc > 2)
	{
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		return -1;
	}
	else
	{
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL)
		{
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return -1;
		}
	}

	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	printf("Device: %s\n", dev);
	printf("Net: %d.%d.%d.%d\n", net & 0xFF, net >> 8 & 0xFF, net >> 16 & 0xFF, net >> 24 & 0xFF);
	printf("Mask: %d.%d.%d.%d\n", mask & 0xFF, mask >> 8 & 0xFF, mask >> 16 & 0xFF, mask >> 24 & 0xFF);

	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (!handle)
    {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

	if (pcap_datalink(handle) != DLT_EN10MB)
	{
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		return -1;
	}
/*
	if (pcap_compile(handle, &fp, FILTER, 0, net) == -1)
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", FILTER, pcap_geterr(handle));
		return -1;
	}

	if (pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", FILTER, pcap_geterr(handle));
		return -1;
	}
*/
	pcap_loop(handle, NUM_PACKAGES, got_packet, NULL);

    pcap_close(handle);

	printf("\nCapture complete.\n");
    return 0;
}
