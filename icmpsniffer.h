#ifndef ICMPSNIFFER_H
#define ICMPSNIFFER_H

#include "defines.h"
#include <QThread>

class ICMPSniffer : public QThread
{
    Q_OBJECT
public:
    explicit ICMPSniffer(const QList<IPID_Info> *info,QObject *parent = 0);
    
protected:
    void run();

signals:
    
public slots:

private:
    const QList<IPID_Info> *m_info;
    
};

#endif // ICMPSNIFFER_H
