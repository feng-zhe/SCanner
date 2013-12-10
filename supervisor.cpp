#include "supervisor.h"
#include "defines.h"
#include "icmpsender.h"
#include "icmpsniffer.h"
#include "tcpconnecter.h"
#include "tcpsfsender.h"
#include "tcpssniffer.h"
#include "tcp_f_sniffer.h"
#include <netinet/in.h> // for big endian to little endian
#include <libnet.h>
#include <QList>
#include <QTime>

Supervisor::Supervisor(QObject *parent) :
    QThread(parent)
{
}

void Supervisor::run()
{
    // emit the start signal
    emit signal_start();
    // ***************First : the ping part******************
    if(m_bICMP){
    // ip address is in network endain,other ids are in host endian
    // recreate the information member
    fillICMPInfo();
    // create the ping sender and receiver
    ICMPSender icmpSend(&m_icmpInfo);
    ICMPSniffer icmpSniff(&m_icmpInfo);
    // connect the signals because the main windows can only notice supervisor's signals
    connect(&icmpSniff,&ICMPSniffer::pingFounded,this,&Supervisor::Founded);
    // start the sniffer first
    icmpSniff.start();
    icmpSend.start();
    icmpSend.wait();
    icmpSniff.wait(500);
    // ask sniffer stop(or it gonna runs forever
    icmpSniff.stop();
    // wait until the threads stopped
    while(icmpSend.isRunning())
        icmpSend.wait(100);
    while(icmpSniff.isRunning())
        icmpSniff.wait(100);
    }

    // recreate tcp info when needed
    if( m_bTCP_C|m_bTCP_S|m_bTCP_F )
        fillTCPInfo();
    // ***************the tcp connect part********************
    if(m_bTCP_C){
    TCPConnecter *threadPool[5];
    QList<TCP_Info> tcpListTemp(m_tcpInfo);
    while(true){
        QList<TCP_Info>::Iterator start=tcpListTemp.begin(),last=tcpListTemp.end();
        int n = last-start;
        if (!n) // no tasks
            break;
        n = n>5 ? 5 : n;
        // create enough threads
        int i=n;
        while(i){
            --i;
            threadPool[i]=new TCPConnecter(*start);
            connect(threadPool[i],&TCPConnecter::tcpcFounded,this,&Supervisor::Founded);
            ++start;
        }
        int j=n;
        // let thread connect
        while(j){
            --j;
            threadPool[j]->start();
            threadPool[j]->wait(1000);
            disconnect(threadPool[j],&TCPConnecter::tcpcFounded,this,&Supervisor::Founded);
            threadPool[j]->exit();
            delete threadPool[j];
        }
        // remove the task we've dealed from list
        tcpListTemp.erase(tcpListTemp.begin(),start);
    }
    }

    // ***************the tcp SYN part********************
    if(m_bTCP_S){
    TCP_SF_Sender tcp_sf_sender_s(&m_tcpInfo,PROTOCOL_TCP_S);
    TCP_S_Sniffer tcp_s_sniffer(&m_tcpInfo);
    connect(&tcp_s_sniffer,&TCP_S_Sniffer::tcp_s_founded,this,&Supervisor::Founded);
    tcp_s_sniffer.start();
    tcp_sf_sender_s.start();
    tcp_sf_sender_s.wait(1000);
    tcp_s_sniffer.wait(2000);
    // ask threads to stop
    tcp_s_sniffer.stop();
    // wait them until they stopped
    while(tcp_sf_sender_s.isRunning())
        tcp_sf_sender_s.wait(100);
    while(tcp_s_sniffer.isRunning())
        tcp_s_sniffer.wait(100);
    }

    // ***************the tcp FIN part********************
    if(m_bTCP_F){
    TCP_SF_Sender tcp_sf_sender_f(&m_tcpInfo,PROTOCOL_TCP_F);
    TCP_F_Sniffer tcp_f_sniffer(&m_tcpInfo);
    connect(&tcp_f_sniffer,&TCP_F_Sniffer::tcp_f_founded,this,&Supervisor::Founded);
    tcp_f_sniffer.start();
    tcp_sf_sender_f.start();
    tcp_sf_sender_f.wait(1000);
    tcp_f_sniffer.wait(2000);
    // ask threads to stop
    tcp_f_sniffer.stop();
    while(tcp_sf_sender_f.isRunning())
        tcp_sf_sender_f.wait(100);
    while(tcp_f_sniffer.isRunning())
        //wait for the sniffer thread's stop.it's longer because the sendResult()
        tcp_f_sniffer.wait(100);
    }

    //*************** over ****************
    // emit finish signal
    emit signal_done();
    return;
}

void Supervisor::fillICMPInfo()
{
    m_icmpInfo.clear();
    IPID_Info info;
    uint hipStart = ntohl(m_ipStart);
    uint hipEnd = ntohl(m_ipEnd);
    // set the random seed
    QTime time;
    time = QTime::currentTime();
    qsrand(time.msec()+time.second()*1000);
    while( hipStart<=hipEnd ){
        info.ip = htonl(hipStart);
        info.IPid = static_cast<ushort>(qrand());
        info.ICMPid = static_cast<ushort>(qrand());
        this->m_icmpInfo.append(info);
        ++hipStart;
    }
}

void Supervisor::fillTCPInfo()
{
    m_tcpInfo.clear();
    TCP_Info info;
    uint hipStart = ntohl(m_ipStart);
    uint hipEnd = ntohl(m_ipEnd);
    ushort port = 0;
    // set the random seed
    QTime time;
    time = QTime::currentTime();
    qsrand(time.msec()+time.second()*1000);
    while( hipStart<=hipEnd ){
        info.ip = htonl(hipStart);
        port = m_portStart;
        while( port<=m_portEnd ){
            info.port = port;
            info.ipID = static_cast<ushort>(qrand());
            info.seq = qrand();
            this->m_tcpInfo.append(info);
            ++port;
        }
        ++hipStart;
    }

}


void Supervisor::stop()
{
    // TODO:
}
