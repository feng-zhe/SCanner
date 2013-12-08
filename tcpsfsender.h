#ifndef TCPSFSENDER_H
#define TCPSFSENDER_H

/* this class is for tcp FIN and SYN. It can send these packets */

#include "defines.h"
#include <QThread>

class TCP_SF_Sender : public QThread
{
    Q_OBJECT
public:
    explicit TCP_SF_Sender(QList<TCP_Info> *info, unsigned int protocol, QObject *parent = 0);

protected:
    void run();

private:
    int tcpSF(unsigned int destip, unsigned short dport, unsigned int seq, unsigned int control, unsigned short IPid);
    
signals:
    
public slots:
    
private:
    const QList<TCP_Info> *m_info;
    unsigned int m_protocol;
};

#endif // TCPSFSENDER_H
