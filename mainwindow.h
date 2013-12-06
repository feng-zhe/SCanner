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

private:
    void start();
    
private:
    Ui::MainWindow *ui;
    QAction *startAction;
    Supervisor *supvisor;   // supervisor who control the procedure of scanning
};

#endif // MAINWINDOW_H
