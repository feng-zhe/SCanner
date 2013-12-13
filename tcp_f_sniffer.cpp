#include "tcp_f_sniffer.h"
#include "defines.h"
#include <QList>
#include <pcap.h>
#include <libnet.h>
#include <netinet/in.h> // for big endian to little endian


TCP_F_Sniffer::TCP_F_Sniffer(const QList<TCP_Info> *info, QObject *parent) :
    QThread(parent),m_info(*info),m_stop(false)
{
}

void TCP_F_Sniffer::stop()
{
    m_stop=true;
}


void TCP_F_Sniffer::run()
{
    // TODO: further upgrade is to find the device by itself
    char dev[] = "eth1";			/* capture device name */
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
    char filter_exp[]="tcp";
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
    const struct libnet_tcp_hdr *tcp; /* The TCP header */
    const u_char *packet;   // the actual packet we picked
    u_int size_ip;  //ip part size
    while(!m_stop){
        packet = pcap_next(handle,&header);
        if( NULL==packet )
            continue;
        ethernet = (struct libnet_ethernet_hdr*)(packet);
        ip = (struct libnet_ipv4_hdr*)(packet + LIBNET_ETH_H);
        size_ip = IP_SIZE(ip);
        tcp = (struct libnet_tcp_hdr*)(packet + LIBNET_ETH_H + size_ip);
        // if this is not RST&ACK, drop it
        if( !((tcp->th_flags&TH_ACK)&&(tcp->th_flags&TH_RST)) )
            continue;
        unsigned int ipSource = ip->ip_src.s_addr;
        unsigned short ipID = ntohs(ip->ip_id);
        unsigned short sport = ntohs(tcp->th_sport);
        unsigned int ack = ntohl(tcp->th_ack);      // should be our sending packet's seq+1
        // check whether the packet is corresponding to our sender
        auto start=m_info.begin(), last=m_info.end();
        while(start!=last){
            if((*start).ip==ipSource && //(*start).ipID==ipID && // some computer don't reply the id(tested)
                    (*start).port==sport && (*start).seq==(ack-1)
                    ){
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

void TCP_F_Sniffer::sendResult()
{
    auto start=m_info.constBegin(),last=m_info.constEnd();
    while(start!=last){
        const TCP_Info &temp = *start;
        emit tcp_f_founded(temp.ip,temp.port,PROTOCOL_TCP_F);
        ++start;
    }
    return;
}
