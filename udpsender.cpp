#include "udpsender.h"
#include "defines.h"
#include <libnet.h>
#include <QList>

UDPSender::UDPSender(const QList<UDP_Info> *info, QObject *parent) :
    QThread(parent),m_info(info)
{
}

void UDPSender::run()
{
    auto start = m_info->constBegin(),
            last = m_info->constEnd();
    while( start!=last ){
        UDP_Info temp=*start;
        // the source port is fixed
        this->udp(temp.ip,temp.ipID,temp.port,25555);
        this->msleep(100);
        ++start;
    }
    return;
}

int UDPSender::udp(uint destip, ushort ipID, ushort dport, ushort sport)
{
    // TODO : now we use the fixed ethernet,we will do something to make it find ethernet by itself
    char dev[DEV_MAX] ;			/* set device name */
    strcpy(dev,global_dev);
    libnet_t *l = NULL;
    libnet_ptag_t packetTag;		// the tag return by some build functions
    char errBuff[LIBNET_ERRBUF_SIZE] = {0};
    // first is to initilize the library and create the envirnoment
    l = libnet_init(LIBNET_RAW4,dev,errBuff);
    if( NULL==l ){
        return -1;
    }

    // create the udp header
    libnet_build_udp(
                sport,
                dport,
                LIBNET_UDP_H,
                0,
                0,
                0,
                l,
                0
                );
    // source ip is my IP
    u_long source;
    source = libnet_get_ipaddr4(l);
    if( -1==int(source) ){
        return -1;
    }
    // create the ip header
    packetTag=libnet_build_ipv4(
                LIBNET_IPV4_H + LIBNET_UDP_H,
                0,
                ipID,             // id
                0,
                60,             // TTL
                IPPROTO_UDP,
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
