#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>

#define SNAP_LEN		1518
#define NUM_PACKAGES	-1

/*
typedef enum RTMPPacketType {
    RTMP_PT_CHUNK_SIZE   =  1,
    RTMP_PT_BYTES_READ   =  3,
    RTMP_PT_PING,
    RTMP_PT_SERVER_BW,
    RTMP_PT_CLIENT_BW,
    RTMP_PT_AUDIO        =  8,
    RTMP_PT_VIDEO,
    RTMP_PT_FLEX_STREAM  = 15,
    RTMP_PT_FLEX_OBJECT,
    RTMP_PT_FLEX_MESSAGE,
    RTMP_PT_NOTIFY,
    RTMP_PT_SHARED_OBJ,
    RTMP_PT_INVOKE,
    RTMP_PT_METADATA     = 22,
} RTMPPacketType;

typedef struct RTMPPacket {
    int            channel_id;
    RTMPPacketType type;
    uint32_t       timestamp;
    uint32_t       ts_field;
    uint32_t       extra;
    uint8_t        *data;
    int            size;
    int            offset;
    int            read;
} RTMPPacket;
*/

void got_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    if (strcmp("publish", (const char*)bytes + 0x45))
    {
        printf("%s\n", bytes + 0x96);
    }
}

int setFilter(pcap_t *dev)
{
    struct bpf_program filter;
    if (pcap_compile(dev, &filter, "dst port 1935", 1, 0))
    {
        printf("bad filter\n");
        return -1;
    }
    if (pcap_setfilter(dev, &filter))
    {
        printf("bad filter\n");
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
	char *dev = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	bpf_u_int32 mask;
	bpf_u_int32 net;


    if (getuid() != 0)
    {
        printf("must be run as root\n");
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

	handle = pcap_open_live(dev, SNAP_LEN, 1, 0, errbuf);
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

	pcap_loop(handle, NUM_PACKAGES, got_packet, NULL);

    pcap_close(handle);

	printf("\nCapture complete.\n");
    return 0;
}
