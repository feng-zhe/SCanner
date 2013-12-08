#ifndef TCPSSNIFFER_H
#define TCPSSNIFFER_H

#include <QThread>
#include "defines.h"

class TCP_S_Sniffer : public QThread
{
    Q_OBJECT
public:
    explicit TCP_S_Sniffer(const QList<TCP_Info> *info, QObject *parent= 0);
    void stop();
    
signals:
    void tcp_s_founded(unsigned int ip, unsigned short port, unsigned short protocol);

protected:
    void run();

public slots:
    
private:
    QList<TCP_Info> m_info;
    bool m_stop;
};

#endif // TCPSSNIFFER_H
