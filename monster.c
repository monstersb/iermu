#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>

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

int checkParam(const char* devName)
{
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    char errMsg[PCAP_ERRBUF_SIZE];
    if (devName == NULL)
    {
        printf("invalid parameter\n");
        return -1;
    }
    if (pcap_lookupnet(devName, &netp, &maskp, errMsg))
    {
        printf("%s\n", errMsg);
        return -1;
    }
    if (getuid() != 0)
    {
        printf("must be run as root\n");
        return -1;
    }
    return 0;
}

pcap_t *openDev(const char *devName)
{
    pcap_t *dev;
    char errMsg[PCAP_ERRBUF_SIZE];
    dev = pcap_open_live(devName, 0x00010000, 1, 0, errMsg);
    if (!dev)
    {
        printf("%s\n", errMsg);
    }
    return dev;
}

void worker(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    if (strcmp("publish", (const char*)bytes + 0x45))
    {
        printf("%s\n", bytes + 0x96);
    }
}

int getPkg(pcap_t *dev)
{
    if (pcap_loop(dev, -1, worker, NULL) < 0)
    {
        printf("an error occured\n");
        return -1;
    }
    return 0;
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
    pcap_t *dev;
    if (checkParam(argv[1]))
    {
        return -1;
    }
    dev = openDev(argv[1]);
    if (!dev)
    {
        return -1;
    }
    if (setFilter(dev))
    {
        return -1;
    }
    if (getPkg(dev))
    {
        return -1;
    }
    pcap_close(dev);
    return 0;
}
