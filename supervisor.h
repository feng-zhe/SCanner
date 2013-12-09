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
    // some threads find something
    void signal_start();   // supervisor start working
    void Founded(unsigned int ip, unsigned short port, unsigned short protocol);
    void signal_done();    // accomplish all tasks
    
public slots:
    void stop();    // ask supervisor to stop
    
public:
    bool m_bICMP;   // indicate whether use icmp scanning
    bool m_bTCP_C;  // indicate whether use tcp_c scanning
    bool m_bTCP_S;  // indicate whether use TCP SYN scanning
    bool m_bTCP_F;  // indicate whether use TCP FIN scanning
};

#endif // SUPERVISOR_H
