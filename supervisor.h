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
    
public slots:
    
};

#endif // SUPERVISOR_H
