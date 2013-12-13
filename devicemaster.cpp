#include "devicemaster.h"
#include "defines.h"
#include <libnet.h>
#include <pcap.h>
#include <QList>
#include <QString>
// the global dev_name variable
char global_dev[DEV_MAX]={0};

DeviceMaster::DeviceMaster():
    m_counter(new PacketCounter)
{
}

DeviceMaster::~DeviceMaster()
{
    delete m_counter;
}

QString DeviceMaster::getDeviceName()
{
    QList<QString> devList;
    // find all the device name
    pcap_if_t *allDevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_findalldevs(&allDevs, errbuf);
    for( pcap_if_t *pDev=allDevs;pDev;pDev=pDev->next ){
        devList.append(QString(pDev->name));
    }
    pcap_freealldevs(allDevs);
    // test the devices we've found
    auto start=devList.constBegin(),
            last=devList.constEnd();
    while(start!=last){
        m_counter->setDevice(*start);
        m_counter->start();
        m_counter->wait(1000);  // wait for a second
        m_counter->stop();
        if(m_counter->isRunning())
            m_counter->wait(100);
        if(m_counter->getCount())
            return *start;
        ++start;
    }
    // test the devices we've found
    return QString("Not founded!");
}


//*************************packetCounter part*********************************
void DeviceMaster::PacketCounter::run()
{
    // reset member datas
    m_stop = false;
    m_count = 0;
    // TODO: we will change dev name to m_dev
    QByteArray ba = m_dev.toLatin1();
    const char *c_dev = ba.data();
    // copy the device name
    char *dev = new char[strlen(c_dev)+1];
    strcpy(dev,c_dev);
    char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
    /* get network number and mask associated with capture device */
    bpf_u_int32 mask;			/* subnet mask */
    bpf_u_int32 net;			/* ip */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
        return;
    /* open capture device */
    pcap_t *handle;				/* packet capture handle */
    //**********better to be promiscuous***********
    handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL)
        return;
    /* make sure we're capturing on an Ethernet device [2] */
    if (pcap_datalink(handle) != DLT_EN10MB)
        return;
    /* compile the filter expression */
    struct bpf_program fp;			/* compiled filter program (expression) */
    char filter_exp[] = "";         // needn't any filter
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
        return;
    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1)
        return;
    /* now we can start capturing packets */
    const u_char *packet;   // the actual packet we picked
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    while(!m_stop){
        packet = pcap_next(handle,&header);
        if( NULL==packet )
            continue;
        else
            ++m_count;
    }

    /* cleanup */
    delete dev;
    pcap_freecode(&fp);
    pcap_close(handle);

    return;
}

DeviceMaster::PacketCounter::PacketCounter(QObject *parent):
    QThread(parent),m_count(0),m_stop(false)
{
}

void DeviceMaster::PacketCounter::setDevice(QString name)
{
    m_dev = name;
}

int DeviceMaster::PacketCounter::getCount() const
{
    return m_count;
}

void DeviceMaster::PacketCounter::stop()
{
    m_stop = true;
}
