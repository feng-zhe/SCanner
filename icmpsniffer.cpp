#include "icmpsniffer.h"
#include "defines.h"

ICMPSniffer::ICMPSniffer(const QList<IPID_Info> *info, QObject *parent) :
    QThread(parent),m_info(info)
{

}

void ICMPSniffer::run()
{

    return;
}
