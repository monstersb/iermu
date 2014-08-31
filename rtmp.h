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
