#ifndef ICMPSENDER_H
#define ICMPSENDER_H

#include <QThread>
#include "defines.h"

class ICMPSender : public QThread
{
    Q_OBJECT
public:
    explicit ICMPSender(const QList<IPID_Info> *list,QObject *parent = 0);

signals:

private:
    int ping(unsigned int dest, unsigned short ICMPid, unsigned short IPid, int repeat); // the actual ping function for inner use

protected:
    void run();
    
private:
    const QList<IPID_Info> *m_list;
};

#endif // ICMPSENDER_H
