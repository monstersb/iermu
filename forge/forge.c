#include <stdio.h>
#include <unistd.h>
#include <librtmp/rtmp.h>
#include <librtmp/amf.h>
#include <arpa/inet.h>

#define url "rtmp://qd.bms.baidu.com:1935/live"

int rtmpconnect(RTMP *rtmp);
int setstreamproperty(RTMP *rtmp);
int releasestream(RTMP *rtmp);
int createstream(RTMP *rtmp);
int publish(RTMP *rtmp);
char *parser(char *data, int mi, int si);

int main(int argc, char *argv[])
{
	RTMPPacket packet;
	char buf[4096];
	RTMP *rtmp = NULL;
	printf("\n");

	rtmp = RTMP_Alloc();
	if (!rtmp)
	{
		fprintf(stderr, "Can not create rtmp\n");
		return -1;
	}

	RTMP_Init(rtmp);

	RTMP_SetupURL(rtmp, url);

	RTMP_EnableWrite(rtmp);

	printf("connecting ...");
	fflush(stdout);
	if (!rtmpconnect(rtmp))
	{
		fprintf(stderr, "Can not connect to server\n");
		return -1;
	}
	while (!(RTMP_ReadPacket(rtmp, &packet) && packet.m_packetType == 20 && packet.m_nBodySize == packet.m_nBytesRead));
	printf("\r");
	printf("Server : %s\n", parser(packet.m_body, 2, 0));
	printf("Code : %s\n", parser(packet.m_body, 3, 1));
	printf("Description : %s\n", parser(packet.m_body, 3, 2));
	printf("Client ID : %s\n", parser(packet.m_body, 3, 6));
	printf("\n");
	printf("waiting ...");
	fflush(stdout);

	if (!setstreamproperty(rtmp))
	{
		fprintf(stderr, "Can not set stream property\n");
		return -1;
	}

	if (RTMP_ReadPacket(rtmp, &packet) && ntohs(*(uint16_t*)packet.m_body) == 0x0006)
	{
		uint32_t trap = ntohl(*(uint32_t*)(packet.m_body + 2));
		printf("\r");
		printf("rtmp ping requests from server : % d\n", trap);
		printf("\n");
		packet.m_nChannel = 0x02;
		packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
		packet.m_packetType = 0x04;
		packet.m_nTimeStamp = 0;
		packet.m_nInfoField2 = 0;
		packet.m_hasAbsTimestamp = 0;
		packet.m_body = buf + RTMP_MAX_HEADER_SIZE;
		*(uint16_t*)packet.m_body = htons(0x07);
		*(uint32_t*)(packet.m_body + 2) = htonl(trap);
		packet.m_nBodySize = 6;
		RTMP_SendPacket(rtmp, &packet, TRUE);  
	}

	printf("creating ...");
	fflush(stdout);
	if (!releasestream(rtmp))
	{
		fprintf(stderr, "Can not release stream\n");
		return -1;
	}
	
	if (!createstream(rtmp))
	{
		fprintf(stderr, "Can not create stream\n");
		return -1;
	}

	if (!publish(rtmp))
	{
		fprintf(stderr, "Can not publish\n");
		return -1;
	}
	while (!(RTMP_ReadPacket(rtmp, &packet) && packet.m_headerType == RTMP_PACKET_SIZE_LARGE && packet.m_nBodySize == packet.m_nBytesRead));
	printf("\r");
	printf("Code : %s\n", parser(packet.m_body, 3, 1));
	printf("Description : %s\n", parser(packet.m_body, 3, 2));
	printf("Client ID : %s\n", parser(packet.m_body, 3, 3));

	printf("\n");

	return 0;
}


int rtmpconnect(RTMP *rtmp)
{
	//return RTMP_Connect(rtmp, NULL);
	
	RTMPPacket packet;
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

	return RTMP_Connect(rtmp, &packet);
}

int setstreamproperty(RTMP *rtmp)
{
    RTMPPacket packet;  
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

	return RTMP_SendPacket(rtmp, &packet, TRUE);
}

int releasestream(RTMP *rtmp)
{
    RTMPPacket packet;  
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

	return RTMP_SendPacket(rtmp, &packet, TRUE);
}

int createstream(RTMP *rtmp)
{  
    RTMPPacket packet;  
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
    return RTMP_SendPacket(rtmp, &packet, TRUE);
}  

int publish(RTMP *rtmp)
{
    RTMPPacket packet;  
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
    return RTMP_SendPacket(rtmp, &packet, TRUE);
}  

char *parser(char *data, int mi, int si)
{
	int i, j;
	char *p = data;
	for (i = 0; i < mi; i++)
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
			p = p + 1 + 2 + ntohs(*(uint16_t*)(p + 1));
			break;
		case AMF_OBJECT:
			p = p + 1;
			while (!(p[0] == '\x00' && p[1] == '\x00' && p[2] == '\x09'))
			{
				p = p + 2 + ntohs(*(uint16_t*)(p));
				switch (*p)
				{
				case AMF_NUMBER:
					p = p + 9;
					break;
				case AMF_BOOLEAN:
					p = p + 2;
					break;
				case AMF_STRING:
					p = p + 1 + 2 + ntohs(*(uint16_t*)(p + 1));
					break;
				case AMF_NULL:
					p = p + 1;
					break;
				}
			}
			p = p + 3;
			break;
		case AMF_NULL:
			p = p + 1;
			break;
		}
	}
	p = p + 1;
	for (j = 0; j < si; j++)
	{
		p = p + 2 + ntohs(*(uint16_t*)(p));
		switch (*p)
		{
		case AMF_NUMBER:
			p = p + 9;
			break;
		case AMF_BOOLEAN:
			p = p + 2;
			break;
		case AMF_STRING:
			p = p + 1 + 2 + ntohs(*(uint16_t*)(p + 1));
			break;
		case AMF_NULL:
			p = p + 1;
			break;
		case AMF_ECMA_ARRAY:
			p = p + 5;			
			while (!(p[0] == '\x00' && p[1] == '\x00' && p[2] == '\x09'))
			{
				p = p + 2 + ntohs(*(uint16_t*)(p));
				switch (*p)
				{
				case AMF_NUMBER:
					p = p + 9;
					break;
				case AMF_BOOLEAN:
					p = p + 2;
					break;
				case AMF_STRING:
					p = p + 1 + 2 + ntohs(*(uint16_t*)(p + 1));
					break;
				case AMF_NULL:
					p = p + 1;
					break;
				}
			}
			p = p + 3;
		}
	}
	p = p + 2 + ntohs(*(uint16_t*)(p));
	return p + 3;
}
