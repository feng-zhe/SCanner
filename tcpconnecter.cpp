#include "tcpconnecter.h"
#include "defines.h"
#include <netinet/in.h> // for big endian to little endian
#include <QTcpSocket>
#include <QHostAddress>

TCPConnecter::TCPConnecter(TCP_Info info, QObject *parent) :
    QThread(parent),m_info(info)
{
}

void TCPConnecter::run()
{
    QTcpSocket client;
    client.connectToHost(QHostAddress(ntohl(m_info.ip)),m_info.port);
    if(client.waitForConnected(1000))
        emit tcpcFounded(m_info.ip,m_info.port,PROTOCOL_TCP_C);
    return;
}
