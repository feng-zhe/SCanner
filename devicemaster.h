#ifndef DEVICEMASTER_H
#define DEVICEMASTER_H
/* this class is used to find information about device */

#include <QThread>

class DeviceMaster
{
public:
    explicit DeviceMaster();
    ~DeviceMaster();
    QString getDeviceName();    // the only function for outside

signals:
    
public slots:

private:
    // inner class
    class PacketCounter;
    PacketCounter *m_counter;
};

// the inner class for actual work
class DeviceMaster::PacketCounter : public QThread
{
    Q_OBJECT
public:
   explicit PacketCounter(QObject *parent=0);
   void setDevice(QString name);
   int getCount() const;
   void stop();
   void run();

private:
   QString m_dev;
   int m_count;
   bool m_stop;
};


#endif // DEVICEMASTER_H
