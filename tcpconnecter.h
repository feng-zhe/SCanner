#ifndef TCPCONNECTER_H
#define TCPCONNECTER_H

#include <QThread>
#include "defines.h"

class TCPConnecter : public QThread
{
    Q_OBJECT
public:
    explicit TCPConnecter(TCP_Info info,QObject *parent = 0);

protected:
    void run();
    
signals:
    void tcpcFounded(unsigned int ip, unsigned short port, unsigned short protocol);
    
public slots:

private:
    TCP_Info m_info;
    
};

#endif // TCPCONNECTER_H
