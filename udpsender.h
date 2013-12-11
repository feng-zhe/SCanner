#ifndef UDPSENDER_H
#define UDPSENDER_H

/* this class is for UDP scan */
#include "defines.h"
#include <QThread>

class UDPSender : public QThread
{
    Q_OBJECT
public:
    explicit UDPSender(const QList<UDP_Info> *info,QObject *parent = 0);
protected:
    void run();
private:
    int udp(uint desip, ushort ipID, ushort dport, ushort sport);


signals:

private:
    const QList<UDP_Info> *m_info;

public slots:
};

#endif // UDPSENDER_H
