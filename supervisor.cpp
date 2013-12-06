#include "supervisor.h"
#include "defines.h"
#include "icmpsender.h"
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
    pdinfo.push_back(IPID_Info({1306151799,2013,2014}));
    ICMPSender icmpSend(&pdinfo);
    icmpSend.start();
    icmpSend.wait();
    return;
}
