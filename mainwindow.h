#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QLabel>
#include <QSpacerItem>
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
    void startScan();
    void addTableItem(unsigned int ip, unsigned short port, unsigned short protocol);
    void lockInput();   // disable the inputs when supvisor is running
    void freeInput();   // free the inputs after the supvisor stopped
    
private:
    // initialized in initialization list
    Ui::MainWindow *ui;
    unsigned int m_rowCount;
    Supervisor *m_supvisor;   // supervisor who control the procedure of scanning
    // initialized in function body
    QMenu *m_menu;
    QToolBar *m_toolBar;
    QAction *m_stopAction;
    QAction *m_startAction;
    QLabel *m_radar;
    QSpacerItem *m_spacer;
};

#endif // MAINWINDOW_H
