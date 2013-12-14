#include "supervisor.h"
#include "defines.h"
#include "icmpsender.h"
#include "icmpsniffer.h"
#include "tcpconnecter.h"
#include "tcpsfsender.h"
#include "tcpssniffer.h"
#include "tcp_f_sniffer.h"
#include "udpsender.h"
#include "udpsniffer.h"
#include "devicemaster.h"
#include <netinet/in.h> // for big endian to little endian
#include <libnet.h>
#include <QString>
#include <QByteArray>
#include <QList>
#include <QTime>

Supervisor::Supervisor(QObject *parent) :
    QThread(parent),m_bStop(false)
{
    connect(this,&Supervisor::signal_stop,this,&Supervisor::stop);
}

void Supervisor::run()
{
    // emit the start signal and reset m_bStop
    emit signal_start();
    m_bStop = false;
    // ***************Zero : set network device name***************
    DeviceMaster devmaster;
    QString devName = devmaster.getDeviceName();
    QByteArray ba = devName.toLatin1();
    // copy the name to global variable globel_dev used by any class which need libnet or libpcap
    strcpy(global_dev,ba.data());

    // ***************First : the ping part******************
    if( m_bICMP && !m_bStop ){
        // ip address is in network endain,other ids are in host endian
        // recreate the information member
        fillICMPInfo();
        // create the ping sender and receiver
        ICMPSender icmpSend(&m_icmpInfo);
        ICMPSniffer icmpSniff(&m_icmpInfo);
        // connect the signals because the main windows can only notice supervisor's signals
        connect(&icmpSniff,&ICMPSniffer::pingFounded,this,&Supervisor::Founded);
        connect(this,&Supervisor::signal_stop,&icmpSniff,&ICMPSniffer::stop);
        // start the sniffer first
        icmpSniff.start();
        icmpSend.start();
        icmpSend.wait();
        icmpSniff.wait(500*m_icmpInfo.length());    // wait for 500ms every icmp test
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
    if( m_bTCP_C && !m_bStop ){
    TCPConnecter *threadPool[5];
    QList<TCP_Info> tcpListTemp(m_tcpInfo);
    while(true){
        auto start=tcpListTemp.begin(),last=tcpListTemp.end();
        int n = last-start;
        if(!n) // no tasks
            break;
        // supvisor is asked to stop
        if(m_bStop)
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
            threadPool[j]->wait(1500);  // it will take longer for tcp connection
            threadPool[j]->exit();
            while(threadPool[j]->isRunning())
                threadPool[j]->wait(100);
            //needn't disconnect since Qt do it for us if the object is deleted
            //disconnect(threadPool[j],&TCPConnecter::tcpcFounded,this,&Supervisor::Founded);
            delete threadPool[j];
        }
        // remove the task we've dealed from list
        tcpListTemp.erase(tcpListTemp.begin(),start);
    }
    }

    // ***************the tcp SYN part********************
    if( m_bTCP_S && !m_bStop ){
        TCP_SF_Sender tcp_sf_sender_s(&m_tcpInfo,PROTOCOL_TCP_S);
        TCP_S_Sniffer tcp_s_sniffer(&m_tcpInfo);
        connect(&tcp_s_sniffer,&TCP_S_Sniffer::tcp_s_founded,this,&Supervisor::Founded);
        connect(this,&Supervisor::signal_stop,&tcp_s_sniffer,&TCP_S_Sniffer::stop);
        tcp_s_sniffer.start();
        tcp_sf_sender_s.start();
        tcp_sf_sender_s.wait();
        tcp_s_sniffer.wait(1000*m_tcpInfo.length());
        // ask threads to stop
        tcp_s_sniffer.stop();
        // wait them until they stopped
        while(tcp_sf_sender_s.isRunning())
            tcp_sf_sender_s.wait(100);
        while(tcp_s_sniffer.isRunning())
            tcp_s_sniffer.wait(100);
    }

    // ***************the tcp FIN part********************
    if( m_bTCP_F && !m_bStop ){
        TCP_SF_Sender tcp_sf_sender_f(&m_tcpInfo,PROTOCOL_TCP_F);
        TCP_F_Sniffer tcp_f_sniffer(&m_tcpInfo);
        connect(&tcp_f_sniffer,&TCP_F_Sniffer::tcp_f_founded,this,&Supervisor::Founded);
        connect(this,&Supervisor::signal_stop,&tcp_f_sniffer,&TCP_F_Sniffer::stop);
        tcp_f_sniffer.start();
        tcp_sf_sender_f.start();
        tcp_sf_sender_f.wait();
        tcp_f_sniffer.wait(1000*m_tcpInfo.length());
        // ask threads to stop
        tcp_f_sniffer.stop();
        while(tcp_sf_sender_f.isRunning())
            tcp_sf_sender_f.wait(100);
        while(tcp_f_sniffer.isRunning())
            //wait for the sniffer thread's stop.it's longer because the sendResult()
            tcp_f_sniffer.wait(100);
    }

    // ***************the UDP part********************
    if( m_bUDP && !m_bStop ){
        fillUDPInfo();
        UDPSender udpSender(&m_udpInfo);
        UDPSniffer udpSniffer(&m_udpInfo);
        connect(&udpSniffer,&UDPSniffer::udp_founded,this,&Supervisor::Founded);
        connect(this,&Supervisor::signal_stop,&udpSniffer,&UDPSniffer::stop);
        udpSniffer.start();
        udpSender.start();
        udpSender.wait();
        udpSniffer.wait(1000*m_udpInfo.length());
        // ask threads to stop
        udpSniffer.stop();
        while(udpSender.isRunning())
            udpSender.wait(100);
        while(udpSniffer.isRunning())
            //wait for the sniffer thread's stop.it's longer because the sendResult()
            udpSniffer.wait(100);
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

void Supervisor::fillUDPInfo()
{
    m_udpInfo.clear();
    UDP_Info info;
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
            this->m_udpInfo.append(info);
            ++port;
        }
        ++hipStart;
    }
}


void Supervisor::stop()
{
    m_bStop = true;
}
