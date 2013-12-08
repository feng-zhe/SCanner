#include "tcpsfsender.h"
#include "defines.h"
#include <libnet.h>

TCP_SF_Sender::TCP_SF_Sender(QList<TCP_Info> *info, unsigned int protocol, QObject *parent) :
    QThread(parent),m_info(info),m_protocol(protocol)
{
}

void TCP_SF_Sender::run()
{
    QList<TCP_Info>::const_iterator start = m_info->constBegin(),
            last = m_info->constEnd();
    while( start!=last ){
        TCP_Info temp=*start;
        uint ctrl;
        switch(m_protocol)
        {
        case PROTOCOL_TCP_S :
            ctrl=TH_SYN;
            break;
        case PROTOCOL_TCP_F:
            ctrl=TH_FIN;
            break;
        default:
            break;
        }

        this->tcpSF(temp.ip,temp.port,temp.seq,ctrl,temp.ipID);
        this->msleep(100);
        ++start;
    }
    return;
}

int TCP_SF_Sender::tcpSF(unsigned int destip, unsigned short dport,unsigned int seq, unsigned int control, unsigned short IPid)
{
    // TODO : now we use the fixed ethernet,we will do something to make it find ethernet by itself
    const char *dev = "eth1";
    libnet_t *l = NULL;
    libnet_ptag_t packetTag;		// the tag return by some build functions
    char errBuff[LIBNET_ERRBUF_SIZE] = {0};
    // first is to initilize the library and create the envirnoment
    l = libnet_init(LIBNET_RAW4,dev,errBuff);
    if( NULL==l ){
        return -1;
    }

    // create the tcp header
    packetTag=libnet_build_tcp(
                25555,		// source port(fixed)
                dport,		// dest port
                seq,		// TODO : seq
                0,			// ack
                control,	// control flags
                0,			// window size
                0,			// checksum (0 for autofill)
                0,			// urgent pointer
                LIBNET_TCP_H,// total length of the TCP packet (for checksum calculation)
                NULL,		// playload
                0,			// playload length
                l,			// the libnet context
                0			// build a new one
                );
    // source ip is my IP
    u_long source;
    source = libnet_get_ipaddr4(l);
    if( -1==int(source) ){
        return -1;
    }
    // create the ip header
    packetTag=libnet_build_ipv4(
                LIBNET_IPV4_H + LIBNET_TCP_H,
                0,
                IPid,             // id
                0,
                60,             // TTL
                IPPROTO_TCP,
                0,
                source,
                destip,
                NULL,
                0,
                l,
                0
                );
    // send packets
    int packet_length = libnet_write(l);
    // destory the session
    libnet_destroy(l);
    return packet_length;
}
