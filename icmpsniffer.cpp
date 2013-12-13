#include "icmpsniffer.h"
#include "defines.h"
#include <libnet.h>
#include <QList>
#include <netinet/in.h> // for big endian to little endian
#include <pcap.h>
#include <QMessageBox> // for debug

ICMPSniffer::ICMPSniffer(const QList<IPID_Info> *info,QObject *parent) :
    QThread(parent),m_info(*info),m_stop(false)
{
}

void ICMPSniffer::stop()
{
    m_stop = true;
}

void ICMPSniffer::run()
{
    char dev[DEV_MAX] ;			/* set device name */
    strcpy(dev,global_dev);
    char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
    /* find a capture device if not specified by dev */
    //dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
        return;

    /* get network number and mask associated with capture device */
    bpf_u_int32 mask;			/* subnet mask */
    bpf_u_int32 net;			/* ip */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
        return;

    /* open capture device */
    pcap_t *handle;				/* packet capture handle */
    handle = pcap_open_live(dev, SNAP_LEN, 0, 1000, errbuf); // needn't to be promiscuous
    if (handle == NULL)
        return;

    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB)
        return;

    /* compile the filter expression */
    struct bpf_program fp;			/* compiled filter program (expression) */
    char filter_exp[] = "icmp";
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
        return;

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1)
        return;

    /* now we can start capturing packets */
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    //const struct libnet_ethernet_hdr *ethernet; /* The ethernet header */
    const struct libnet_ipv4_hdr *ip; /* The IP header */
    const struct libnet_icmpv4_hdr *icmp; /* The ICMP header */
    const u_char *packet;   // the actual packet we picked
    u_int size_ip;
    while(!m_stop){
        packet = pcap_next(handle,&header);
        if( NULL==packet )
            continue;
        //ethernet = (struct libnet_ethernet_hdr*)(packet);
        ip = (struct libnet_ipv4_hdr*)(packet + LIBNET_ETH_H);
        size_ip = IP_SIZE(ip);
        icmp = (struct libnet_icmpv4_hdr*)(packet + LIBNET_ETH_H + size_ip);
        unsigned int ipSource = ip->ip_src.s_addr;
        //unsigned short ipID = ntohs(ip->ip_id);
        unsigned short icmpID = ntohs(icmp->hun.echo.id);
        // check whether the packet is corresponding to our sender
        QList<IPID_Info>::iterator start=m_info.begin(), last=m_info.end();
        while(start!=last){
            // check if the response is corresponding to my ping
            if((*start).ip==ipSource && //(*start).IPid==ipID && //!!!!!!!!!!!!! sina don't reply the same!
                    (*start).ICMPid==icmpID){
                emit pingFounded(ipSource,0,PROTOCOL_ICMP);
                m_info.erase(start);    // to avoid the duplicate table row same icmp response
                break;
            }
            ++start;
        }
    }

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

    return;
}
