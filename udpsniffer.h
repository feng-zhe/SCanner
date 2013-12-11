#ifndef UDPSNIFFER_H
#define UDPSNIFFER_H

/* this class restore the ports which don't reponse,
 * so we can read the m_info and know which port is on
 * just like TCP_F
 */
#include <QThread>
#include "defines.h"

class UDPSniffer : public QThread
{
    Q_OBJECT
public:
    explicit UDPSniffer(const QList<UDP_Info>*info, QObject *parent = 0);
    void stop();

signals:
    void udp_founded(unsigned int ip, unsigned short port, unsigned short protocol);

protected:
    void run();

private:
    void sendResult();

public slots:

private:
    QList<UDP_Info> m_info;
    bool m_stop;
};

#endif // UDPSNIFFER_H
