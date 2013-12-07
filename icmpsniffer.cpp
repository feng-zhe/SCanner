#include "icmpsniffer.h"
#include "defines.h"
#include <libnet.h>
#include <netinet/in.h> // for big endian to little endian
#include <pcap.h>
#include <QMessageBox> // for debug

ICMPSniffer::ICMPSniffer(QObject *parent) :
    QThread(parent)
{
}

// initialize the static variable
QList<IPID_Info> ICMPSniffer::m_info=QList<IPID_Info>();

void ICMPSniffer::setInfo(const QList<IPID_Info> *info)
{
    m_info.append(*info);
}

void ICMPSniffer::run()
{
    char dev[] = "eth1";			/* capture device name */
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
    char filter_exp[] = "icmp and ip dst 10.187.247.7";
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
        return;

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1)
        return;

    /* now we can set our callback function and start the loop */
    pcap_loop(handle,-1, callBack, (u_char*)this);

    /* cleanup */
    pcap_freecode(&fp);
    pcap_close(handle);

    return;
}

void ICMPSniffer::callBack(u_char *args, const pcap_pkthdr *header, const u_char *packet)
{
    ICMPSniffer *pointer = (ICMPSniffer*)args;
    const struct libnet_ethernet_hdr *ethernet; /* The ethernet header */
    const struct libnet_ipv4_hdr *ip; /* The IP header */
    const struct libnet_icmpv4_hdr *icmp; /* The ICMP header */
    u_int size_ip;
    ethernet = (struct libnet_ethernet_hdr*)(packet);
    ip = (struct libnet_ipv4_hdr*)(packet + LIBNET_ETH_H);
    size_ip = IP_SIZE(ip);
    icmp = (struct libnet_icmpv4_hdr*)(packet + LIBNET_ETH_H + size_ip);
    // corresponding to how to store in m_info
    unsigned int ipSource = ip->ip_src.s_addr;
    unsigned short ipID = ntohs(ip->ip_id);
    unsigned short icmpID = ntohs((icmp->hun).echo.id);

    QList<IPID_Info>::const_iterator start=m_info.constBegin(), last=m_info.constEnd();
    while(start!=last){
        // check if the response is corresponding to my ping
        if((*start).ip==ipSource && (*start).IPid==ipID && (*start).ICMPid==icmpID){
            pointer->emitPingFounded(ipSource,icmpID,ipID);
        }
        ++start;
    }
    return;
}


void ICMPSniffer::emitPingFounded(unsigned int ip, unsigned short icmpID, unsigned short ipID)
{
    emit pingFound(ip,icmpID,ipID);
}
