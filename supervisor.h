#ifndef SUPERVISOR_H
#define SUPERVISOR_H

#include <QThread>

/* this class is used to control the whole procedure of scanning */
class Supervisor : public QThread
{
    Q_OBJECT
public:
    explicit Supervisor(QObject *parent = 0);

protected:
    void run();

signals:
    void pingFounded(unsigned int ip, unsigned short icmpID, unsigned short ipID);
    
public slots:
    
};

#endif // SUPERVISOR_H
