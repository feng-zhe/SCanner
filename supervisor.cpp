#include "supervisor.h"
#include "defines.h"
#include "icmpsender.h"
#include "icmpsniffer.h"
#include "tcpconnecter.h"
#include "tcpsfsender.h"
#include "tcpssniffer.h"
#include <libnet.h>
#include <QList>
#include <QDebug>

Supervisor::Supervisor(QObject *parent) :
    QThread(parent)
{
}

void Supervisor::run()
{
    // ***************First : the ping part******************
    // TO DO: for debug
    if(0){
    // TO DO: now we just test the IP and id's
    QList<IPID_Info> pdinfo;
    // ip address is in network endain,other ids are in host endian
    // make the task info list
    pdinfo.push_back(IPID_Info({1306151799,2013,2014}));
    // create the ping sender and receiver
    ICMPSender icmpSend(&pdinfo);
    ICMPSniffer icmpSniff(&pdinfo);
    // connect the signals because the main windows can only notice supervisor's signals
    connect(&icmpSniff,&ICMPSniffer::pingFound,this,&Supervisor::Founded);
    // start the sniffer first
    icmpSniff.start();
    icmpSend.start();
    icmpSend.wait();
    icmpSniff.wait(2000);
    icmpSniff.quit();
    }

    // ***************the tcp connect part********************
    // TODO: for debug
    QList<TCP_Info> tcpList;
    TCP_Info temp;
    temp.ip = 1306151799;
    temp.ipID = 2013;
    temp.port = 80;
    temp.seq = 100;
    tcpList.push_back(temp);
    // TO DO: for the debug
    if(0){
    TCPConnecter *threadPool[5];
    while(true){
        QList<TCP_Info>::Iterator start=tcpList.begin(),last=tcpList.end();
        int n = last-start;
        if (!n) // no tasks
            break;
        n = n>5 ? 5 : n;
        // create enough threads
        int i=n;
        qDebug()<<i;
        while(i){
            --i;
            threadPool[i]=new TCPConnecter(*start);
            connect(threadPool[i],&TCPConnecter::tcpcFounded,this,&Supervisor::Founded);
            ++start;
        }
        int j=n;
        while(j){
            --j;
            threadPool[j]->start();
            threadPool[j]->wait(1000);
            disconnect(threadPool[j],&TCPConnecter::tcpcFounded,this,&Supervisor::Founded);
            threadPool[j]->exit();
            delete threadPool[j];
        }
        // remove the task we've dealed from list
        tcpList.erase(tcpList.begin(),start);
    }
    }

    // ***************the tcp SYN part********************
    TCP_SF_Sender tcp_sf_sender(&tcpList,PROTOCOL_TCP_S);
    TCP_S_Sniffer tcp_s_sniffer(&tcpList);
    connect(&tcp_s_sniffer,&TCP_S_Sniffer::tcp_s_founded,this,&Supervisor::Founded);
    tcp_s_sniffer.start();
    tcp_sf_sender.start();
    tcp_sf_sender.wait(1000);
    tcp_s_sniffer.wait(1000);
    tcp_s_sniffer.stop();
    this->msleep(500);  //wait for the sniffer thread's stop
    if(tcp_sf_sender.isRunning())
        tcp_sf_sender.exit();
    if(tcp_s_sniffer.isRunning())
        tcp_s_sniffer.exit();



    // ***************the tcp FIN part********************

    return;
}
