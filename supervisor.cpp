#include "supervisor.h"
#include "defines.h"
#include "icmpsender.h"
#include "icmpsniffer.h"
#include <libnet.h>
#include <QList>


Supervisor::Supervisor(QObject *parent) :
    QThread(parent)
{
}

void Supervisor::run()
{
    // TO DO: now we just test the IP and id's
    QList<IPID_Info> pdinfo;
    // ip address is in network endain,ids are in host endian
    pdinfo.push_back(IPID_Info({1306151799,2013,2014}));
    // create the ping sender
    ICMPSender icmpSend(&pdinfo);
    // create the ping receiver
    ICMPSniffer icmpSniff;
    icmpSniff.setInfo(&pdinfo);
    // connect the signals because the main windows can only notice supervisor's signals
    connect(&icmpSniff,&ICMPSniffer::pingFound,this,&Supervisor::pingFounded);
    // start the sniffer first
    icmpSniff.start();
    icmpSend.start();
    icmpSend.wait();
    icmpSniff.wait(2000);
    icmpSniff.quit();
    return;
}
