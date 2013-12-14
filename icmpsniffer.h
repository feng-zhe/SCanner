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

protected:
    void run();

public slots:
    void stop();

signals:
    void pingFounded(unsigned int ip, unsigned short port, unsigned short protocol);
    
private:
    QList<IPID_Info> m_info;  // this member is copy of the arg of setInfo
    bool m_stop;
    
};

#endif // ICMPSNIFFER_H
