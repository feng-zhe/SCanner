#ifndef TCP_F_SNIFFER_H
#define TCP_F_SNIFFER_H
/* this class restore the ports which don't reponse,
 * so we can read the m_info and know which port is on
 */
#include <QThread>
#include "defines.h"

class TCP_F_Sniffer : public QThread
{
    Q_OBJECT
public:
    explicit TCP_F_Sniffer(const QList<TCP_Info> *info, QObject *parent = 0);
    void stop();
    
signals:
    void tcp_f_founded(unsigned int ip, unsigned short port, unsigned short protocol);

protected:
    void run();

private:
    void sendResult();
    
public slots:
    
private:
    QList<TCP_Info> m_info;
    bool m_stop;
};

#endif // TCP_F_SNIFFER_H
