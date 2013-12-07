#ifndef ICMPSNIFFER_H
#define ICMPSNIFFER_H

#include "defines.h"
#include <pcap.h>
#include <QThread>

class ICMPSniffer : public QThread
{
    Q_OBJECT
public:
    explicit ICMPSniffer(QObject *parent = 0);
    void setInfo(const QList<IPID_Info> *info);

protected:
    void run();

private:
    static void callBack(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

signals:
    void pingFound(unsigned int ip,unsigned short icmpID,unsigned short ipID);
    
public slots:
    void emitPingFounded(unsigned int ip,unsigned short icmpID,unsigned short ipID);

private:
   static QList<IPID_Info> m_info;  // this member is copy of the arg of setInfo
    
};

#endif // ICMPSNIFFER_H
