#include "udpsniffer.h"
#include "defines.h"
#include <QList>
#include <pcap.h>
#include <libnet.h>
#include <netinet/in.h> // for big endian to little endian

UDPSniffer::UDPSniffer(const QList<UDP_Info>*info, QObject *parent):
    QThread(parent),m_info(*info),m_stop(false)
{
}

void UDPSniffer::stop()
{
    m_stop = true;
}


void UDPSniffer::run()
{
    // TODO: further upgrade is to find the device by itself
    char dev[DEV_MAX] ;			/* set device name */
    strcpy(dev,global_dev);
    char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
    /* find a capture device if not specified on command-line */
    //dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        return;
    }

    /* get network number and mask associated with capture device */
    bpf_u_int32 mask;			/* subnet mask */
    bpf_u_int32 net;			/* ip */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        return;
    }

    /* open capture device */
    pcap_t *handle;				/* packet capture handle */
    handle = pcap_open_live(dev, SNAP_LEN, 0, 1000, errbuf); // needn't to be promiscuous
    if (handle == NULL) {
        return;
    }

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        return;
    }

    /* compile the filter expression */
    struct bpf_program fp;			/* compiled filter program (expression) */
    char filter_exp[]="icmp";
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        return;
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        return;
    }

    /* now we can set our callback function */
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    const struct libnet_ethernet_hdr *ethernet; /* The ethernet header */
    const struct libnet_ipv4_hdr *ip; /* The IP header */
    const struct libnet_icmpv4_hdr *icmp; /* The icmp header */
    const u_char *packet;   // the actual packet we picked
    u_int size_ip;  //ip part size
    while(!m_stop){
        packet = pcap_next(handle,&header);
        if( NULL==packet )
            continue;
        ethernet = (struct libnet_ethernet_hdr*)(packet);
        ip = (struct libnet_ipv4_hdr*)(packet + LIBNET_ETH_H);
        size_ip = IP_SIZE(ip);
        icmp = (struct libnet_icmpv4_hdr*)(packet + LIBNET_ETH_H + size_ip);
        // if this is not ICMP PORT UNREACHABLE, drop it
        if( !(icmp->icmp_code&ICMP_UNREACH_PORT) )
            continue;
        unsigned int ipSource = ip->ip_src.s_addr;
        //unsigned short ipID = ntohs(ip->ip_id);
        // check whether the packet is corresponding to our sender
        auto start=m_info.begin(), last=m_info.end();
        while(start!=last){
            if((*start).ip==ipSource){// except the ip, nothing can be checked(ipID is not same sometimes)
                // then this port is not open, erase it.
                m_info.erase(start);
                break;
            }
            ++start;
        }
    }
    // sending the result
    this->sendResult();
    /* cleanup */
    pcap_freecode(&fp);     /* free the fileter */
    pcap_close(handle);     /* free the session */
}

void UDPSniffer::sendResult()
{
    auto start=m_info.constBegin(),last=m_info.constEnd();
    while(start!=last){
        const UDP_Info &temp = *start;
        emit udp_founded(temp.ip,temp.port,PROTOCOL_UDP);
        ++start;
    }
    return;
}
