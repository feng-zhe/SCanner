#ifndef ICMPSNIFFER_H
#define ICMPSNIFFER_H

#include "defines.h"
#include <pcap.h>
#include <QThread>

class ICMPSniffer : public QThread
{
    Q_OBJECT
public:
    explicit ICMPSniffer(const QList<IPID_Info> *info,QObject *parent = 0);
    void stop();

protected:
    void run();

private:
    static void callBack(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

signals:
    void pingFounded(unsigned int ip, unsigned short port, unsigned short protocol);
    
public slots:
    void emitPingFounded(unsigned int ip, unsigned short port, unsigned short protocol);

private:
    QList<IPID_Info> m_info;  // this member is copy of the arg of setInfo
    bool m_stop;
    
};

#endif // ICMPSNIFFER_H
