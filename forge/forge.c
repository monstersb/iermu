#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <librtmp/rtmp.h>
#include <librtmp/amf.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <string.h>
#include <libkern/OSAtomic.h>

#define url "rtmp://hz.bms.baidu.com:1935/live"
#define TIMEOUT	3

#define flvfilename	"./video.flv"

#define HTON16(x)  ((x>>8&0xff)|(x<<8&0xff00))
#define HTON24(x)  ((x>>16&0xff)|(x<<16&0xff0000)|(x&0xff00))
#define HTON32(x)  ((x>>24&0xff)|(x>>8&0xff00)|(x<<8&0xff0000)|(x<<24&0xff000000))
#define HTONTIME(x) ((x>>16&0xff)|(x<<16&0xff0000)|(x&0xff00)|(x&0xff000000))

typedef enum
{ 
	RTMP_LOGCRIT = 0, 
	RTMP_LOGERROR, 
	RTMP_LOGWARNING, 
	RTMP_LOGINFO,
	RTMP_LOGDEBUG, 
	RTMP_LOGDEBUG2, 
	RTMP_LOGALL
} RTMP_LogLevel;

void RTMP_LogSetOutput(FILE *file);
void RTMP_LogSetLevel(RTMP_LogLevel lvl);

volatile int32_t cmdcount = 0;
long tstart;
long tframe;
long tlast;

pthread_mutex_t mutex  = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutexcmd  = PTHREAD_MUTEX_INITIALIZER;

int rtmpconnect(RTMP *rtmp);
int setstreamproperty(RTMP *rtmp);
int setstreamproperty1(RTMP *rtmp);
int releasestream(RTMP *rtmp);
int createstream(RTMP *rtmp);
int publish(RTMP *rtmp);
int setdataframe(RTMP *rtmp);
char *parser(char *data, int len);
void *receiver(void *arg);
void dispatch(RTMP *rtmp, RTMPPacket *packet);
int sendpacket(RTMP *rtmp, RTMPPacket *packet);
int sendvideo(RTMP *rtmp);



int ReadU8(uint32_t *u8, FILE *fp)
{
	if (fread(u8, 1, 1, fp) != 1)
	{
		return 0;
	}
	return 1;
}

int ReadU16(uint32_t *u16, FILE *fp)
{
	if (fread(u16, 2, 1, fp) != 1)
	{
		return 0;
	}
	*u16 = HTON16(*u16);
	return 1;
}

int ReadU24(uint32_t *u24, FILE *fp)
{
	if (fread(u24, 3, 1, fp) != 1)
	{
		return 0;
	}
	*u24 = HTON24(*u24);
	return 1;
}

int ReadU32(uint32_t *u32, FILE *fp)
{
	if (fread(u32, 4, 1, fp) != 1)
	{
		return 0;
	}
	*u32 = HTON32(*u32);
	return 1;
}

int PeekU8(uint32_t *u8, FILE *fp)
{
	if (fread(u8, 1, 1, fp) != 1)
	{
		return 0;
	}
	fseek(fp, -1, SEEK_CUR);
	return 1;
}

int ReadTime(uint32_t *utime, FILE *fp)
{
	if (fread(utime, 4, 1, fp) != 1)
	{
		return 0;
	}
	*utime = HTONTIME(*utime);
	return 1;
}

int main(int argc, char *argv[])
{
	RTMP *rtmp = NULL;
	pthread_t ntid;
	printf("\n");

	rtmp = RTMP_Alloc();
	if (!rtmp)
	{
		fprintf(stderr, "Can not create rtmp\n");
		return -1;
	}

	//RTMP_LogSetOutput(fopen("rtmp.log", "a+"));
	//RTMP_LogSetLevel(RTMP_LOGCRIT);
	RTMP_LogSetLevel(RTMP_LOGINFO);

	RTMP_Init(rtmp);

	RTMP_SetupURL(rtmp, url);

	RTMP_EnableWrite(rtmp);

	rtmp->Link.timeout = TIMEOUT;

	pthread_create(&ntid, NULL, receiver, (void*)rtmp);

	printf("##Connecting ......\n");
	if (!rtmpconnect(rtmp))
	{
		fprintf(stderr, "Can not connect to server\n");
		return -1;
	}

	printf("##Setting stream property ......\n");
	if (!setstreamproperty(rtmp))
	{
		fprintf(stderr, "Can not set stream property\n");
		return -1;
	}

	printf("##Release stream ......\n");
	if (!releasestream(rtmp))
	{
		fprintf(stderr, "Can not release stream\n");
		return -1;
	}
	
	printf("##Creating stream ......\n");
	if (!createstream(rtmp))
	{
		fprintf(stderr, "Can not create stream\n");
		return -1;
	}

	printf("##Publishing ......\n");
	if (!publish(rtmp))
	{
		fprintf(stderr, "Can not publish\n");
		return -1;
	}

	printf("##Setting data frame ......\n");
	if (!setdataframe(rtmp))
	{
		fprintf(stderr, "Can not set data frame\n");
		return -1;
	}

	printf("Setting stream property ......\n");
	if (!setstreamproperty(rtmp))
	{
		fprintf(stderr, "Can not set stream property\n");
		return -1;
	}

	tstart = time(NULL) - 1;
	tframe = 0;
	tlast = 0;

	do
	{
		printf("Start to send video data ......\n");
	} while (sendvideo(rtmp));

	pthread_join(ntid, NULL);

	return 0;
}

int sendvideo(RTMP *rtmp)
{
	RTMPPacket *packet;
	uint32_t type = 0;
	uint32_t datalength = 0;
	uint32_t timestamp = 0;
	uint32_t streamid = 0;
	uint32_t alldatalength = 0;
	int iret;
	int bNextIsKey = 1;
	FILE *fp;
	int fsize;
	
	fp = fopen(flvfilename, "rb");
	if (fp == NULL)
	{
		fprintf(stderr, "Can not open flv file (%s)\n", strerror(errno));
		return -1;
	}
	fseek(fp, 0, SEEK_END);
	fsize = ftell(fp);

	fseek(fp, 0, SEEK_SET);
	fseek(fp, 9, SEEK_SET);
	fseek(fp, 4, SEEK_CUR);
	packet = (RTMPPacket*)malloc(sizeof(RTMPPacket));
	memset(packet, 0, sizeof(RTMPPacket));
	RTMPPacket_Alloc(packet, 1024 * 64);
	RTMPPacket_Reset(packet);
	
	while (1)
	{
		if ((time(NULL) - tstart) < (tframe / 1000) && bNextIsKey)
		{
			if(tframe > tlast)
			{
				tlast = tframe;
			}
			sleep(1);
			continue;
		}	
		
		if (!ReadU8(&type, fp))
		{
			break;
		}
		if (!ReadU24(&datalength, fp))
		{
			break;
		}
		if(!ReadTime(&timestamp, fp))
		{
			break;
		}
		if(!ReadU24(&streamid, fp))
		{
			break;
		}
		if (type != RTMP_PACKET_TYPE_VIDEO && type != 0x08)
		{
			fseek(fp, datalength + 4, SEEK_CUR);
			continue;
		}

		if (fread(packet->m_body, 1, datalength, fp) != datalength)
		{
			break;
		}


		packet->m_headerType = RTMP_PACKET_SIZE_MEDIUM; 
		packet->m_hasAbsTimestamp = 0;
		packet->m_nChannel = 0x04;
		packet->m_nInfoField2 = rtmp->m_stream_id;
		packet->m_nTimeStamp = timestamp; 
		packet->m_packetType = type;
		packet->m_nBodySize = datalength;

		iret = RTMP_SendPacket(rtmp, packet, FALSE);
		if (!ReadU32(&alldatalength, fp))
		{
			break;
		}
		tframe = tlast;
		bNextIsKey = 0;
		if (!PeekU8(&type, fp))
		{
			break;
		}
		if (type == 0x09)
		{
			if (fseek(fp, 11, SEEK_CUR) != 0)
			{
				break;
			}
			if (!PeekU8(&type, fp))
			{
				break;
			}
			if (type == 0x17)
			{
				bNextIsKey = 1;
			}
			fseek(fp, -11, SEEK_CUR);
		}
	}
	fclose(fp);
	return iret;
}

int sendpacket(RTMP *rtmp, RTMPPacket *packet)
{
	pthread_mutex_lock(&mutex);
	int iret = RTMP_SendPacket(rtmp, packet, TRUE);
	pthread_mutex_unlock(&mutex);
	return iret;
}

int rtmpconnect(RTMP *rtmp)
{
	//return RTMP_Connect(rtmp, NULL);
	
	RTMPPacket packet;
	int iret;
	char pbuf[4096];
	char *pend = pbuf + sizeof(pbuf);
	char *enc;
	AVal av_conn = AVC("connect");
	AVal av_app = AVC("app");
	AVal av_mapp = AVC("live");
	AVal av_type = AVC("type");
	AVal av_nonprivate = AVC("nonprivate");
	AVal av_tcurl = AVC("tcUrl");
	AVal av_url = AVC(url);
	AVal av_guid = AVC("guid");
	AVal av_guidv = AVC("GUID");
	AVal av_fpad = AVC("fpad");
	AVal av_capabilities = AVC("capabilities");
	AVal av_audioCodecs = AVC("audioCodecs");
	AVal av_videoCodecs = AVC("videoCodecs");
	AVal av_videoFunction = AVC("videoFunction");
	AVal av_objectEncoding = AVC("objectEncoding");
	AVal av_publishtoken = AVC("publishtoken");
	AVal av_publishtokenv = AVC("PUBLISHTOKEN");
	AVal av_devid = AVC("devid");
	AVal av_devidv = AVC("137893012267");
	AVal av_devtype = AVC("devtype");
	AVal av_devtypev = AVC("1");
	AVal av_accesstoken = AVC("accesstoken");
	AVal av_accesstokenv = AVC("21.e416d444f5d271c34a1a5ba02af54535.2592000.1411917032.2488534000-1508471");
	AVal av_extjson = AVC("extjson");
	AVal av_extjsonv = AVC("{\"property\":1}");

	packet.m_nChannel = 0x03;
	packet.m_headerType = RTMP_PACKET_SIZE_LARGE;
	packet.m_packetType = 0x14;
	packet.m_nTimeStamp = 0;
	packet.m_nInfoField2 = 0;
	packet.m_hasAbsTimestamp = 0;
	packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

	enc = packet.m_body;
	enc = AMF_EncodeString(enc, pend, &av_conn);
	enc = AMF_EncodeNumber(enc, pend, ++rtmp->m_numInvokes);
	*enc++ = AMF_OBJECT;

	enc = AMF_EncodeNamedString(enc, pend, &av_app, &av_mapp);

	enc = AMF_EncodeNamedString(enc, pend, &av_type, &av_nonprivate);
	enc = AMF_EncodeNamedString(enc, pend, &av_tcurl, &av_url);
	enc = AMF_EncodeNamedString(enc, pend, &av_guid, &av_guidv);
	enc = AMF_EncodeNamedBoolean(enc, pend, &av_fpad, FALSE);
	enc = AMF_EncodeNamedNumber(enc, pend, &av_capabilities, 15);
	enc = AMF_EncodeNamedNumber(enc, pend, &av_audioCodecs, 3575);
	enc = AMF_EncodeNamedNumber(enc, pend, &av_videoCodecs, 252);
	enc = AMF_EncodeNamedNumber(enc, pend, &av_videoFunction, 1);
	enc = AMF_EncodeNamedNumber(enc, pend, &av_objectEncoding, 3);
	enc = AMF_EncodeNamedString(enc, pend, &av_publishtoken, &av_publishtokenv);
	enc = AMF_EncodeNamedString(enc, pend, &av_devid, &av_devidv);
	enc = AMF_EncodeNamedString(enc, pend, &av_accesstoken, &av_accesstokenv);
	enc = AMF_EncodeNamedString(enc, pend, &av_devtype, &av_devtypev);
	enc = AMF_EncodeNamedString(enc, pend, &av_extjson, &av_extjsonv);

	*enc++ = 0;
	*enc++ = 0;
	*enc++ = AMF_OBJECT_END;

	packet.m_nBodySize = enc - packet.m_body;


	pthread_mutex_lock(&mutex);
	iret = RTMP_Connect(rtmp, &packet);
	pthread_mutex_unlock(&mutex);
	while (cmdcount != rtmp->m_numInvokes)
	{
		sleep(0);
	}
	return iret;
}

int setstreamproperty(RTMP *rtmp)
{
    RTMPPacket packet;  
	int iret;
    char pbuf[4096];
	char *pend = pbuf + sizeof(pbuf);  
    char *enc;  
	AVal av_setStreamProperty = AVC("setStreamProperty");
	AVal av_extParams = AVC("extParams");
	AVal av_extParamsv = AVC("{\"pts_high\":0,\"pts_low\":0}");
	AVal av_streamproperty = AVC("streamproperty");

    packet.m_nChannel = 0x03;
    packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;  
    packet.m_packetType = 0x14; 
    packet.m_nTimeStamp = 0;  
    packet.m_nInfoField2 = 0;  
    packet.m_hasAbsTimestamp = 0;  
	packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

    enc = packet.m_body;  
	enc = AMF_EncodeString(enc, pend, &av_setStreamProperty);
	enc = AMF_EncodeNumber(enc, pend, ++rtmp->m_numInvokes);
	*enc++ = '\x05';
	*enc++ = AMF_OBJECT;
	enc = AMF_EncodeNamedNumber(enc, pend, &av_streamproperty, 1);
	enc = AMF_EncodeNamedString(enc, pend, &av_extParams, &av_extParamsv);

	*enc++ = 0;
	*enc++ = 0;
	*enc++ = AMF_OBJECT_END;

	packet.m_nBodySize = enc - packet.m_body;

	iret = sendpacket(rtmp, &packet);
	OSAtomicIncrement32(&cmdcount);
	return iret;
}

int setstreamproperty1(RTMP *rtmp)
{
    RTMPPacket packet;  
	int iret;
    char pbuf[4096];
	char *pend = pbuf + sizeof(pbuf);  
    char *enc;  
	AVal av_setStreamProperty = AVC("setStreamProperty");
	AVal av_extParams = AVC("extParams");
	AVal av_extParamsv = AVC("{\"pts_high\":328140,\"pts_low\":3322696058}");
	AVal av_streamproperty = AVC("streamproperty");

    packet.m_nChannel = 0x03;
    packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;  
    packet.m_packetType = 0x14; 
    packet.m_nTimeStamp = 0;  
    packet.m_nInfoField2 = 0;  
    packet.m_hasAbsTimestamp = 0;  
	packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

    enc = packet.m_body;  
	enc = AMF_EncodeString(enc, pend, &av_setStreamProperty);
	enc = AMF_EncodeNumber(enc, pend, ++rtmp->m_numInvokes);
	*enc++ = '\x05';
	*enc++ = AMF_OBJECT;
	enc = AMF_EncodeNamedNumber(enc, pend, &av_streamproperty, 5);
	enc = AMF_EncodeNamedString(enc, pend, &av_extParams, &av_extParamsv);

	*enc++ = 0;
	*enc++ = 0;
	*enc++ = AMF_OBJECT_END;

	packet.m_nBodySize = enc - packet.m_body;

	iret = sendpacket(rtmp, &packet);
	OSAtomicIncrement32(&cmdcount);
	return iret;
}

int releasestream(RTMP *rtmp)
{
    RTMPPacket packet;  
	int iret;
    char pbuf[4096];
	char *pend = pbuf + sizeof(pbuf);  
    char *enc;  
	AVal av_releaseStream = AVC("releaseStream");
	AVal av_streamid = AVC("b4ac44242cce11e4aa0900259089e31a");
  
    packet.m_nChannel = 0x03;
    packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;  
    packet.m_packetType = 0x14; 
    packet.m_nTimeStamp = 0;  
    packet.m_nInfoField2 = 0;  
    packet.m_hasAbsTimestamp = 0;  
    packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;  

    enc = packet.m_body;  

	enc = AMF_EncodeString(enc, pend, &av_releaseStream);
	enc = AMF_EncodeNumber(enc, pend, ++rtmp->m_numInvokes);
    *enc++ = AMF_NULL; 
	enc = AMF_EncodeString(enc, pend, &av_streamid);

	packet.m_nBodySize = enc - packet.m_body;

	iret = sendpacket(rtmp, &packet);
	while (cmdcount != rtmp->m_numInvokes)
	{
		sleep(0);
	}
	return iret;
}

int createstream(RTMP *rtmp)
{  
    RTMPPacket packet;  
	int iret;
    char pbuf[4096];
	char *pend = pbuf + sizeof(pbuf);  
    char *enc;  
	AVal av_releaseStream = AVC("createStream");
  
    packet.m_nChannel = 0x03;
    packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;  
    packet.m_packetType = 0x14; 
    packet.m_nTimeStamp = 0;  
    packet.m_nInfoField2 = 0;  
    packet.m_hasAbsTimestamp = 0;  
    packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;  
 
    enc = packet.m_body;  
  
	enc = AMF_EncodeString(enc, pend, &av_releaseStream);
	enc = AMF_EncodeNumber(enc, pend, ++rtmp->m_numInvokes);
    *enc++ = AMF_NULL; 

    packet.m_nBodySize = enc - packet.m_body;
    iret = sendpacket(rtmp, &packet);
	while (cmdcount != rtmp->m_numInvokes)
	{
		sleep(0);
	}
	return iret;
}  

int publish(RTMP *rtmp)
{
    RTMPPacket packet;  
	int iret;
    char pbuf[4096];
	char *pend = pbuf + sizeof(pbuf);  
    char *enc;  
	AVal av_publish = AVC("publish");
	AVal av_streamid = AVC("b4ac44242cce11e4aa0900259089e31a");
	AVal av_live = AVC("live");
	AVal av_dynamictoken = AVC("dynamictoken");
	AVal av_stub_dynamictoken = AVC("stub_dynamictoken");
	AVal av_streamproperty = AVC("streamproperty");
  
    packet.m_nChannel = 0x04;
    packet.m_headerType = RTMP_PACKET_SIZE_LARGE;  
    packet.m_packetType = 0x14; 
    packet.m_nTimeStamp = 0;  
    packet.m_nInfoField2 = 1;  
    packet.m_hasAbsTimestamp = 0;  
    packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;  
 
    enc = packet.m_body;  
  
	enc = AMF_EncodeString(enc, pend, &av_publish);
	enc = AMF_EncodeNumber(enc, pend, ++rtmp->m_numInvokes);
	*enc++ = AMF_OBJECT;
	enc = AMF_EncodeNamedString(enc, pend, &av_dynamictoken, &av_stub_dynamictoken);
	enc = AMF_EncodeNamedNumber(enc, pend, &av_streamproperty, 1);
	*enc++ = 0;  
	*enc++ = 0;
    *enc++ = AMF_OBJECT_END;  
	enc = AMF_EncodeString(enc, pend, &av_streamid);
	enc = AMF_EncodeString(enc, pend, &av_live);

    packet.m_nBodySize = enc - packet.m_body;
    iret = sendpacket(rtmp, &packet);
	OSAtomicIncrement32(&cmdcount);
	return iret;
}  

char *parserarray(char *data, int layer)
{
	char *p = data;
	double number;
	char tstr[1024];
	int i = 0;
	if (*p == AMF_OBJECT)
	{
		p = p + 1;
		while (!(p[0] == '\x00' && p[1] == '\x00' && p[2] == '\x09'))
		{
			int namelen;
			namelen = ntohs(*(uint16_t*)(p));
			for (i = 0; i < layer; i++)
			{
				printf("\t");
			}
			memcpy(tstr, p + 2, namelen);
			tstr[namelen] = '\0';
			printf("\t%s : ", tstr);
			p = p + 2 + namelen;
			switch (*p)
			{
			case AMF_NUMBER:
				number = AMF_DecodeNumber(p + 1);
				printf("%lf\n", number);
				p = p + 9;
				break;
			case AMF_BOOLEAN:
				printf(*(p + 1) ? "TRUE\n" : "FALSE\n");
				p = p + 2;
				break;
			case AMF_STRING:
				printf("%s\n", p + 3);
				p = p + 1 + 2 + ntohs(*(uint16_t*)(p + 1));
				break;
			case AMF_NULL:
				printf("NULL\n");
				p = p + 1;
				break;
			case AMF_UNDEFINED:
				printf("Undefined\n");
				p = p + 1;
				break;
			case AMF_ECMA_ARRAY:
			case AMF_OBJECT:
				printf("\n");
				p = parserarray(p, layer + 1);
				break;
			}
		}
		p = p + 3;
	}
	else if (*p == AMF_ECMA_ARRAY)
	{
		int len;
		p = p + 1;
		len = ntohl(*(uint32_t*)(p));
		p = p + 4;
		while (!(p[0] == '\x00' && p[1] == '\x00' && p[2] == '\x09') && len--)
		{
			int namelen;
			namelen = ntohs(*(uint16_t*)(p));
			for (i = 0; i < layer; i++)
			{
				printf("\t");
			}
			memcpy(tstr, p + 2, namelen);
			tstr[namelen] = '\0';
			printf("\t%s : ", tstr);
			p = p + 2 + namelen;
			switch (*p)
			{
			case AMF_NUMBER:
				number = AMF_DecodeNumber(p + 1);
				printf("%lf\n", number);
				p = p + 9;
				break;
			case AMF_BOOLEAN:
				printf(*(p + 1) ? "TRUE\n" : "FALSE\n");
				p = p + 2;
				break;
			case AMF_STRING:
				printf("%s\n", p + 3);
				p = p + 1 + 2 + ntohs(*(uint16_t*)(p + 1));
				break;
			case AMF_NULL:
				printf("NULL\n");
				p = p + 1;
				break;
			case AMF_UNDEFINED:
				printf("Undefined\n");
				p = p + 1;
				break;
			case AMF_ECMA_ARRAY:
			case AMF_OBJECT:
				printf("\n");
				p = parserarray(p, layer + 1);
				break;
			}
		}
		p = p + 3;
	}
	return p;
}

char *parser(char *data, int len)
{
	char *p = data;
	while (p - data < len)
	{
		switch (*p)
		{
		case AMF_NUMBER:
			p = p + 9;
			break;
		case AMF_BOOLEAN:
			p = p + 2;
			break;
		case AMF_STRING:
			printf("%s\n", p + 3);
			p = p + 1 + 2 + ntohs(*(uint16_t*)(p + 1));
			break;
		case AMF_UNDEFINED:
			printf("Undefined\n");
			p = p + 1;
			break;
		case AMF_OBJECT:
		case AMF_ECMA_ARRAY:
			p = parserarray(p, 1);
			break;
		case AMF_NULL:
			p = p + 1;
			break;
		}
	}
	//printf("-----------------------------------------------------------------------------------\n");
	return 0;
}

int setdataframe(RTMP *rtmp)
{
    RTMPPacket packet;  
    char pbuf[4096];
	char *pend = pbuf + sizeof(pbuf);  
    char *enc;  
	AVal av_setDataFrame = AVC("@setDataFrame");
	AVal av_onMetaData = AVC("onMetaData");
	AVal av_duration = AVC("duration");
	AVal av_width = AVC("width");
	AVal av_height = AVC("height");
	AVal av_videodatarate = AVC("videodatarate");
	AVal av_framerate = AVC("framerate");
	AVal av_videocodecid = AVC("videocodecid");
	AVal av_audiodatarate = AVC("audiodatarate");
	AVal av_audiosamplerate = AVC("audiosamplerate");
	AVal av_audiosamplesize = AVC("audiosamplesize");
	AVal av_stereo = AVC("stereo");
	AVal av_audiocodecid = AVC("audiocodecid");
	AVal av_encoder = AVC("encoder");
	AVal av_encoderv = AVC("Lavf54.59.106");
	AVal av_filesize = AVC("filesize");
	AVal av_absRecordTime = AVC("absRecordTime");
  
    packet.m_nChannel = 0x04;
    packet.m_headerType = RTMP_PACKET_SIZE_LARGE;  
    packet.m_packetType = 0x12; 
    packet.m_nTimeStamp = 0;  
    packet.m_nInfoField2 = 0;  
    packet.m_hasAbsTimestamp = 0;  
    packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;  
 
    enc = packet.m_body;  
  
	enc = AMF_EncodeString(enc, pend, &av_setDataFrame);
	enc = AMF_EncodeString(enc, pend, &av_onMetaData);
	*enc++ = AMF_ECMA_ARRAY;
	*(uint32_t*)enc = htonl(14);
	enc = enc + 4;
	enc = AMF_EncodeNamedNumber(enc, pend, &av_duration, 0);
	enc = AMF_EncodeNamedNumber(enc, pend, &av_width, 1280);
	enc = AMF_EncodeNamedNumber(enc, pend, &av_height, 720);
	enc = AMF_EncodeNamedNumber(enc, pend, &av_videodatarate, 400);
	enc = AMF_EncodeNamedNumber(enc, pend, &av_framerate, 10);
	enc = AMF_EncodeNamedNumber(enc, pend, &av_videocodecid, 7);
	enc = AMF_EncodeNamedNumber(enc, pend, &av_audiodatarate, 43.06640625);
	enc = AMF_EncodeNamedNumber(enc, pend, &av_audiosamplerate, 11025);
	enc = AMF_EncodeNamedNumber(enc, pend, &av_audiosamplesize, 16);
	enc = AMF_EncodeNamedBoolean(enc, pend, &av_stereo, FALSE);
	enc = AMF_EncodeNamedNumber(enc, pend, &av_audiocodecid, 160);
	enc = AMF_EncodeNamedString(enc, pend, &av_encoder, &av_encoderv);
	enc = AMF_EncodeNamedNumber(enc, pend, &av_filesize, 0);
	enc = AMF_EncodeNamedNumber(enc, pend, &av_absRecordTime, 1409353891205); ///////////
	*enc++ = 0;  
	*enc++ = 0;
    *enc++ = AMF_OBJECT_END;  
    *enc++ = AMF_NULL; 

    packet.m_nBodySize = enc - packet.m_body;
    return sendpacket(rtmp, &packet);
}  

void *receiver(void *arg)
{
	RTMP* rtmp = (RTMP*)arg;
	RTMPPacket packet;
	while (1)
	{
		pthread_mutex_lock(&mutex);
		bzero(&packet, sizeof(packet));
		RTMP_ReadPacket(rtmp, &packet);
		if (packet.m_nBodySize == packet.m_nBytesRead)
		{
			dispatch(rtmp, &packet);
		}
		RTMPPacket_Free(&packet);
		pthread_mutex_unlock(&mutex);
		sleep(0);
	}
	return 0;
}

void dispatchpingrequest(RTMP* rtmp, RTMPPacket *packet);
void dispatchacknowledgement(RTMP *rtmp, RTMPPacket *packet);
void dispatchcmd(RTMP *rtmp, RTMPPacket *packet);
void dispatch06(RTMP *rtmp, RTMPPacket *packet);
void dispatchctrlmsg(RTMP *rtmp, RTMPPacket *packet);

void dispatch(RTMP *rtmp, RTMPPacket *packet)
{
	if (packet->m_nChannel == 2 && ntohs(*(uint16_t*)packet->m_body) == 0x0006)
	{
		dispatchpingrequest(rtmp, packet);
	}
	if (packet->m_packetType == 0x04)
	{
		dispatchctrlmsg(rtmp, packet);
	}
	if (packet->m_packetType == 0x05)
	{
		dispatchacknowledgement(rtmp, packet);
	}
	if (packet->m_packetType == 0x06)
	{
		dispatch06(rtmp, packet);
	}
	if (packet->m_packetType == 0x14)
	{
		dispatchcmd(rtmp, packet);
	}
}

void dispatchpingrequest(RTMP *rtmp, RTMPPacket *packet)
{
	RTMPPacket r_packet;	
	char buf[4096];
	uint32_t trap = ntohl(*(uint32_t*)(packet->m_body + 2));
	printf("rtmp ping requests from server : % d\n", trap);
	r_packet.m_nChannel = 0x02;
	r_packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
	r_packet.m_packetType = 0x04;
	r_packet.m_nTimeStamp = 0;
	r_packet.m_nInfoField2 = 0;
	r_packet.m_hasAbsTimestamp = 0;
	r_packet.m_body = buf + RTMP_MAX_HEADER_SIZE;
	*(uint16_t*)r_packet.m_body = htons(0x07);
	*(uint32_t*)(r_packet.m_body + 2) = htonl(trap);
	r_packet.m_nBodySize = 6;
	RTMP_SendPacket(rtmp, &r_packet, TRUE);  
}

void resultconnect(char *buffer);

void dispatchcmd(RTMP *rtmp, RTMPPacket *packet)
{
	//AVal av_result = AVC("_result");
	//AVal *av_resultv = (AVal*)(packet->m_body + 1);
	if (*packet->m_body == 0x02)
		//&& !AVMATCH(av_resultv, &av_result))
	{
		AVal av_str;
		double id;
		char *p = (char*)packet->m_body + 1;
		AMF_DecodeString(p ,&av_str);
		p = p + 2 + av_str.av_len + 1;
		id = AMF_DecodeNumber(p);
		p = p + 9;
		printf("Command result: %d\n", (int)id);
		parser(packet->m_body, packet->m_nBodySize);
		OSAtomicIncrement32(&cmdcount);
	}

}

void dispatchacknowledgement(RTMP *rtmp, RTMPPacket *packet)
{
	printf("Window acknowledgement size: %d\n", ntohl(*(uint32_t*)(packet->m_body)));
}

void dispatch06(RTMP *rtmp, RTMPPacket *packet)
{
}

void dispatchctrlmsg(RTMP *rtmp, RTMPPacket *packet)
{
	if (ntohs(*(uint16_t*)(packet->m_body)) == 0)
	{
		printf("Stream Begin\n");
	}
}
