#include "icmpsender.h"
#include <libnet.h>
#include <QList>
#include "defines.h"

ICMPSender::ICMPSender(const QList<IPID_Info> *list, QObject *parent):
    QThread(parent),m_list(list)
{
}

void ICMPSender::run()
{
    // send 5 pings for every ip address
    QList<IPID_Info>::const_iterator begin = m_list->constBegin(),
            end = m_list->constEnd();
    while( begin!=end ){
        IPID_Info info = *begin;
        this->ping(info.ip,info.ICMPid,info.IPid,5);
        this->msleep(200);
        ++begin;
    }
    return;
}

int ICMPSender::ping(unsigned int dest,unsigned short ICMPid,unsigned short IPid,int repeat)// return -1 means wrong,the bytes written on right
{
    // TO DO : now we use the fixed ethernet,we will do something to make it find ethernet by itself
    // eth1 is my wireless ethernet card
    const char *dev = "eth1";
    libnet_t *l = NULL;
    char errBuff[LIBNET_ERRBUF_SIZE] = {0};
    // first is to initilize the library and create the envirnoment
    l = libnet_init(LIBNET_RAW4,dev,errBuff);
    if( NULL==l ){
        return -1;
    }
    // create the icmp header
    libnet_build_icmpv4_echo(
            ICMP_ECHO,
            0,
            0,
            ICMPid, //id
            456,   //packet sequence number
            NULL,
            0,
            l,
            0
            );
    // source ip is my IP
    u_long source = libnet_get_ipaddr4(l);
    if( -1==int(source) ){
        return -1;
    }
    // destination ip is the parameter "ip"
    // create the ip header
    libnet_build_ipv4(
            LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H,
            0,
            IPid,             // id
            0,
            60,             // TTL
            IPPROTO_ICMP,
            0,
            source,
            dest,
            NULL,
            0,
            l,
            0
            );
    // send packets
    int packet_length = libnet_write(l);
    // repeat
    for(int i=0;i<repeat-1;++i)
        libnet_write(l);
    // destory the session
    libnet_destroy(l);
    return packet_length;
}
