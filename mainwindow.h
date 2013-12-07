#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include "supervisor.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT
    
public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

public slots:
    void start();
    void addTableItem(unsigned int ip, unsigned short icmpID, unsigned short ipID);
    
private:
    Ui::MainWindow *ui;
    unsigned int rowCount;
    QAction *startAction;
    Supervisor *supvisor;   // supervisor who control the procedure of scanning
};

#endif // MAINWINDOW_H
